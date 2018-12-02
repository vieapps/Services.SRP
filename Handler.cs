#region Related components
using System;
using System.Net;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Configuration;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Caching;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.SRP
{
	public class Handler
	{
		RequestDelegate Next { get; }
		bool RedirectToNoneWWW { get; set; } = true;
		bool RedirectToHTTPS { get; set; } = false;
		string DefaultDirectory { get; set; } = "apps";
		string DefaultFile { get; set; } = "index.html";
		Dictionary<string, Map> Maps { get; } = new Dictionary<string, Map>(StringComparer.OrdinalIgnoreCase);

		public Handler(RequestDelegate next)
		{
			this.Next = next;
			if (ConfigurationManager.GetSection("net.vieapps.services.srp.maps") is AppConfigurationSectionHandler config)
			{
				// global settings
				this.RedirectToNoneWWW = "true".IsEquals(config.Section.Attributes["redirectToNoneWWW"]?.Value);
				this.RedirectToHTTPS = "true".IsEquals(config.Section.Attributes["redirectToHTTPS"]?.Value);
				this.DefaultDirectory = config.Section.Attributes["defaultDirectory"]?.Value ?? "apps";
				this.DefaultDirectory = Path.IsPathRooted(this.DefaultDirectory) ? this.DefaultDirectory : Path.Combine(Global.RootPath, this.DefaultDirectory);
				this.DefaultFile = config.Section.Attributes["defaultFile"]?.Value ?? "index.html";

				// individual settings
				if (config.Section.SelectNodes("map") is System.Xml.XmlNodeList maps)
					maps.ToList().ForEach(map =>
					{
						var host = map.Attributes["host"]?.Value;
						if (!string.IsNullOrWhiteSpace(host))
						{
							var folder = map.Attributes["folder"]?.Value;
							if (!string.IsNullOrWhiteSpace(folder))
							{
								if (folder.IndexOf(Path.DirectorySeparatorChar) < 0)
									folder = Path.Combine(this.DefaultDirectory, folder);
								this.Maps[host.Trim().ToLower()] = new Map
								{
									Host = host.Trim().ToLower(),
									Folder = Directory.Exists(folder) ? folder : Path.Combine(this.DefaultDirectory, folder),
									NotFound = map.Attributes["notFound"]?.Value,
									RedirectToNoneWWW = map.Attributes["redirectToNoneWWW"]?.Value != null ? "true".IsEquals(map.Attributes["redirectToNoneWWW"]?.Value) : this.RedirectToNoneWWW,
									RedirectToHTTPS = map.Attributes["redirectToHTTPS"]?.Value != null ? "true".IsEquals(map.Attributes["redirectToHTTPS"]?.Value) : this.RedirectToHTTPS
								};
							}
						}
					});
			}
			Global.Logger.LogInformation(
				$"=> Redirect to none WWW: {this.RedirectToNoneWWW}" + "\r\n" +
				$"=> Redirect to HTTPs: {this.RedirectToHTTPS}" + "\r\n" +
				$"=> Default directory: {this.DefaultDirectory}" + "\r\n" +
				$"=> Default file: {this.DefaultFile}" + "\r\n" +
				$"=> Maps: {(this.Maps.Count < 1 ? "None" : $"\r\n\t+ {string.Join("\r\n\t+ ", this.Maps.Select(m => $"{m.Key} => {m.Value.Folder + $" ({m.Value.RedirectToNoneWWW}/{m.Value.RedirectToHTTPS}/{m.Value.NotFound ?? "None"})"}"))}")}"
			);
		}

		public async Task Invoke(HttpContext context)
		{
			// load balancing health check
			if (context.Request.Path.Value.IsEquals("/load-balancing-health-check"))
				await context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			else
			{
				// process the request
				await this.ProcessRequestAsync(context).ConfigureAwait(false);

				// invoke next middleware
				try
				{
					await this.Next.Invoke(context).ConfigureAwait(false);
				}
				catch (InvalidOperationException) { }
				catch (Exception ex)
				{
					Global.Logger.LogCritical($"Error occurred while invoking the next middleware: {ex.Message}", ex);
				}
			}
		}

		#region Process request
		async Task ProcessRequestAsync(HttpContext context)
		{
			//  prepare
			context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
			var requestUri = context.GetRequestUri();
			if (Global.IsDebugLogEnabled)
				await context.WriteLogsAsync("SRP", $"Begin request {requestUri}");

			// request of static files
			if (Global.StaticSegments.Contains(requestUri.GetRequestPathSegments().First()))
				await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

			// only allow GET method
			else if (!context.Request.Method.IsEquals("GET"))
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());

			// process
			else
				try
				{
					var fileInfo = await this.ProcessFileRequestAsync(context).ConfigureAwait(false);
					if (fileInfo != null && Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("SRP", $"Success response ({fileInfo.FullName} - {fileInfo.Length:#,##0} bytes)").ConfigureAwait(false);
				}
				catch (Exception ex)
				{
					await context.WriteLogsAsync("SRP", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
					context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
				}
		}

		bool GetMap(string host, out Map mapInfo)
		   => this.Maps.TryGetValue(host, out mapInfo)
			   ? true
			   : host.IsStartsWith("www.")
				   ? this.Maps.TryGetValue(host.Right(host.Length - 4), out mapInfo)
				   : false;

		async Task<FileInfo> ProcessFileRequestAsync(HttpContext context)
		{
			// prepare
			var requestUri = context.GetRequestUri();
			this.GetMap(requestUri.Host, out Map mapInfo);

			// redirect
			var redirectToHttps = (mapInfo != null ? mapInfo.RedirectToHTTPS : this.RedirectToHTTPS) && !requestUri.Scheme.IsEquals("https");
			var redirectToNoneWWW = (mapInfo != null ? mapInfo.RedirectToNoneWWW : this.RedirectToNoneWWW) && requestUri.Host.StartsWith("www.");
			if (redirectToHttps || redirectToNoneWWW)
			{
				var url = $"{requestUri}";
				url = redirectToHttps ? url.Replace("http://", "https://") : url;
				url = redirectToNoneWWW ? url.Replace("://www.", "://") : url;
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("SRP", $"Redirect: {requestUri} => {url}");
				context.Redirect(url);
				return null;
			}

			// prepare file info
			FileInfo fileInfo = null;
			var filePath = $"{mapInfo?.Folder ?? this.DefaultDirectory}/{string.Join("/", requestUri.GetRequestPathSegments())}".Replace(@"\", "/").Replace("//", "/").Replace('/', Path.DirectorySeparatorChar);
			filePath += filePath.EndsWith(Path.DirectorySeparatorChar) ? this.DefaultFile : "";

			// check to reduce traffic
			var eTag = "SRP#" + $"{requestUri}".ToLower().GenerateUUID();
			if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")))
			{
				var isNotModified = true;
				var lastModifed = DateTime.Now.ToUnixTimestamp();
				if (context.GetHeaderParameter("If-Modified-Since") != null)
				{
					fileInfo = new FileInfo(filePath);
					if (fileInfo.Exists)
					{
						lastModifed = fileInfo.LastWriteTime.ToUnixTimestamp();
						isNotModified = lastModifed <= context.GetHeaderParameter("If-Modified-Since").FromHttpDateTime().ToUnixTimestamp();
					}
					else
						isNotModified = false;
				}
				if (isNotModified)
				{
					context.SetResponseHeaders((int)HttpStatusCode.NotModified, eTag, lastModifed, "public", context.GetCorrelationID());
					if (Global.IsDebugLogEnabled)
						await context.WriteLogsAsync("SRP", $"Success response with status code 304 to reduce traffic ({filePath})").ConfigureAwait(false);
					return fileInfo;
				}
			}

			// check existed
			fileInfo = fileInfo ?? new FileInfo(filePath);
			if (!fileInfo.Exists && !string.IsNullOrWhiteSpace(mapInfo?.NotFound))
				fileInfo = new FileInfo(Path.Combine(Path.IsPathRooted(mapInfo.Folder) ? mapInfo.Folder : Path.Combine(this.DefaultDirectory, mapInfo.Folder), mapInfo.NotFound));
			if (!fileInfo.Exists)
				throw new FileNotFoundException($"Not Found [{requestUri}]");

			// prepare body
			var fileMimeType = fileInfo.GetMimeType();
			var fileContent = fileMimeType.IsEndsWith("json")
				? JObject.Parse(await UtilityService.ReadTextFileAsync(fileInfo, null, Global.CancellationTokenSource.Token).ConfigureAwait(false)).ToString(Formatting.Indented).ToBytes()
				: await UtilityService.ReadBinaryFileAsync(fileInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);

			// response
			context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
			{
				{ "Content-Type", $"{fileMimeType}; charset=utf-8" },
				{ "ETag", eTag },
				{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
				{ "Cache-Control", "public" },
				{ "Expires", $"{DateTime.Now.AddMinutes(13).ToHttpString()}" },
				{ "X-CorrelationID", context.GetCorrelationID() }
			});
			await context.WriteAsync(fileContent, Global.CancellationTokenSource.Token).ConfigureAwait(false);
			return fileInfo;
		}
		#endregion

		#region Helper: WAMP connections
		internal static void OpenWAMPChannels(int waitingTimes = 6789)
		{
			Global.Logger.LogInformation($"Attempting to connect to WAMP router [{WAMPConnections.GetRouterStrInfo()}]");
			Global.OpenWAMPChannels(
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Incoming channel to WAMP router is established - Session ID: {args.SessionId}");
					WAMPConnections.IncomingChannel.Update(WAMPConnections.IncomingChannelSessionID, Global.ServiceName, $"Incoming ({Global.ServiceName} HTTP service)");
					Global.InterCommunicateMessageUpdater = WAMPConnections.IncomingChannel.RealmProxy.Services
						.GetSubject<CommunicateMessage>("net.vieapps.rtu.communicate.messages.pwas")
						.Subscribe(
							async message => await Handler.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
							exception => Global.WriteLogs(Global.Logger, "RTU", $"{exception.Message}", exception)
						);
				},
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Outgoing channel to WAMP router is established - Session ID: {args.SessionId}");
					WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)");
					try
					{
						Task.WaitAll(new[] {
							Global.InitializeLoggingServiceAsync(),
							Global.InitializeRTUServiceAsync()
						}, waitingTimes > 0 ? waitingTimes : 6789, Global.CancellationTokenSource.Token);
						Global.Logger.LogInformation("Helper services are succesfully initialized");
					}
					catch (Exception ex)
					{
						Global.Logger.LogError($"Error occurred while initializing helper services: {ex.Message}", ex);
					}
				},
				waitingTimes
			);
		}

		static Task ProcessInterCommunicateMessageAsync(CommunicateMessage message) => Task.CompletedTask;
		#endregion

	}

	public class Map
	{
		public string Host { get; internal set; } = "";
		public string Folder { get; internal set; } = "";
		public bool RedirectToNoneWWW { get; internal set; } = false;
		public bool RedirectToHTTPS { get; internal set; } = false;
		public string NotFound { get; internal set; } = null;
	}
}