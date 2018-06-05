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
using System.Xml;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using WampSharp.V2.Core.Contracts;

using net.vieapps.Components.Caching;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.PWAs
{
	public class Handler
	{
		RequestDelegate Next { get; }

		public Handler(RequestDelegate next)
		{
			this.Next = next;
			this.Prepare();
		}

		public async Task Invoke(HttpContext context)
		{
			// only allow GET method
			if (!context.Request.Method.IsEquals("GET"))
			{
				context.ShowHttpError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());
				return;
			}

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

		#region Prepare attributes
		bool AlwaysUseSecureConnections { get; set; } = true;

		bool RedirectToNoneWWW { get; set; } = true;

		string DefaultFolder { get; set; } = "PWAs";

		Dictionary<string, string> Maps { get; set; } = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

		void Prepare()
		{
			this.AlwaysUseSecureConnections = "true".IsEquals(UtilityService.GetAppSetting("PWAs:AlwaysUseSecureConnections", "true"));
			this.RedirectToNoneWWW = "true".IsEquals(UtilityService.GetAppSetting("PWAs:RedirectToNoneWWW", "true"));
			this.DefaultFolder = UtilityService.GetAppSetting("PWAs:DefaultFolder", "PWAs");
			if (this.DefaultFolder.IndexOf(Path.DirectorySeparatorChar) < 0)
				this.DefaultFolder = Path.Combine(Global.RootPath, this.DefaultFolder);

			if (ConfigurationManager.GetSection("net.vieapps.maps") is AppConfigurationSectionHandler config)
				if (config.Section.SelectNodes("map") is XmlNodeList maps)
					maps.ToList().ForEach(map =>
					{
						var host = map.Attributes["host"]?.Value;
						if (!string.IsNullOrWhiteSpace(host))
						{
							var folder = map.Attributes["folder"]?.Value;
							if (!string.IsNullOrWhiteSpace(folder))
							{
								if (folder.IndexOf(Path.DirectorySeparatorChar) < 0)
									folder = Path.Combine(this.DefaultFolder, folder);
								this.Maps[host] = Directory.Exists(folder) ? folder : Path.Combine(this.DefaultFolder, map.Attributes["folder"].Value);
							}
						}
					});

			Global.Logger.LogInformation(
				$"==> Always use secure connections: {this.AlwaysUseSecureConnections}" + "\r\n" +
				$"==> Redirect to none WWW: {RedirectToNoneWWW}" + "\r\n" +
				$"==> Default folder: {DefaultFolder}" + "\r\n" +
				$"==> Maps: \r\n\t\t{string.Join("\r\n\t\t", this.Maps.Select(m => $"{m.Key} -> {m.Value}"))}"
			);
		}
		#endregion

		#region Process request
		internal async Task ProcessRequestAsync(HttpContext context)
		{
			// prepare
			var requestUri = context.GetRequestUri();
			var pathSegments = requestUri.GetRequestPathSegments();

			// redirect
			var needRedirect = (this.AlwaysUseSecureConnections && !requestUri.Scheme.IsEquals("https")) || (this.RedirectToNoneWWW && requestUri.Host.IsStartsWith("www"));
			if (needRedirect && !Global.StaticSegments.Contains(pathSegments[0]))
			{
				var url = this.AlwaysUseSecureConnections && !requestUri.Scheme.IsEquals("https")
					? $"{requestUri}".Replace("http://", "https://")
					: $"{requestUri}";

				url = this.RedirectToNoneWWW && requestUri.Host.IsStartsWith("www")
					? url.Replace("://www.", "://")
					: url;

				context.Redirect(url);
				return;
			}

			// process the request
			try
			{
				// prepare
				context.Items["PipelineStopwatch"] = Stopwatch.StartNew();
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("PWAs", $"Begin request {requestUri}");
				FileInfo fileInfo = null;

				var filePath = (Global.StaticSegments.Contains(pathSegments[0])
					? pathSegments[0].IsEquals("statics")
						? UtilityService.GetAppSetting("Path:StaticFiles", Global.RootPath + "/data-files/statics".Replace('/', Path.DirectorySeparatorChar))
						: Global.RootPath
					: this.Maps.TryGetValue(requestUri.Host, out string folder)
						? folder
						: requestUri.Host.StartsWith("www.") && this.Maps.TryGetValue(requestUri.Host.Right(requestUri.Host.Length - 4), out folder)
							? folder
							: this.DefaultFolder) + ("/" + string.Join("/", pathSegments)).Replace("//", "/").Replace(@"\", "/").Replace('/', Path.DirectorySeparatorChar);
				if (Global.StaticSegments.Contains(pathSegments[0]) && pathSegments[0].IsEquals("statics"))
					filePath = filePath.Replace($"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}", $"{Path.DirectorySeparatorChar}statics{Path.DirectorySeparatorChar}");
				if (filePath.EndsWith(Path.DirectorySeparatorChar))
					filePath += "index.html";

				// headers to reduce traffic
				var eTag = "PWAs#" + $"{requestUri}".ToLower().GenerateUUID();
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
							await context.WriteLogsAsync("PWAs", $"Success response with status code 304 to reduce traffic ({filePath})").ConfigureAwait(false);
						return;
					}
				}

				// check existed
				fileInfo = fileInfo ?? new FileInfo(filePath);
				if (!fileInfo.Exists)
					throw new FileNotFoundException($"Not Found [{requestUri}]");

				// prepare body
				var fileMimeType = fileInfo.GetMimeType();
				var fileContent = fileMimeType.IsEndsWith("json")
					? JObject.Parse(await UtilityService.ReadTextFileAsync(fileInfo, null, Global.CancellationTokenSource.Token).ConfigureAwait(false)).ToString(Newtonsoft.Json.Formatting.Indented).ToBytes()
					: await UtilityService.ReadBinaryFileAsync(fileInfo, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// response
				context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>
				{
					{ "Content-Type", $"{fileMimeType}; charset=utf-8" },
					{ "ETag", eTag },
					{ "Last-Modified", $"{fileInfo.LastWriteTime.ToHttpString()}" },
					{ "Cache-Control", "public" },
					{ "Expires", $"{DateTime.Now.AddDays(7).ToHttpString()}" },
					{ "X-CorrelationID", context.GetCorrelationID() }
				});
				await Task.WhenAll(
					context.WriteAsync(fileContent, Global.CancellationTokenSource.Token),
					!Global.IsDebugLogEnabled ? Task.CompletedTask : context.WriteLogsAsync("PWAs", $"Success response ({filePath} - {fileInfo.Length:#,##0} bytes)")
				).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				await context.WriteLogsAsync("PWAs", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
				context.ShowHttpError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
			}
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
							async (message) => await Handler.ProcessInterCommunicateMessageAsync(message).ConfigureAwait(false),
							exception => Global.WriteLogs(Global.Logger, "RTU", $"{exception.Message}", exception)
						);
				},
				(sender, args) =>
				{
					Global.Logger.LogInformation($"Outgoing channel to WAMP router is established - Session ID: {args.SessionId}");
					WAMPConnections.OutgoingChannel.Update(WAMPConnections.OutgoingChannelSessionID, Global.ServiceName, $"Outgoing ({Global.ServiceName} HTTP service)");
					try
					{
						Task.WaitAll(new[] { Global.InitializeLoggingServiceAsync(), Global.InitializeRTUServiceAsync() }, waitingTimes > 0 ? waitingTimes : 6789, Global.CancellationTokenSource.Token);
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
}