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
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;
using net.vieapps.Components.Caching;
using net.vieapps.Components.Security;
using net.vieapps.Components.Utility;
#endregion

namespace net.vieapps.Services.SRP
{
	public class Handler
	{

		#region Properties
		bool RedirectToNoneWWW { get; set; } = true;

		bool RedirectToHTTPS { get; set; } = false;

		string DefaultDirectory { get; set; } = "apps";

		string DefaultFile { get; set; } = "index.html";

		string LoadBalancerHealthCheckURL { get; } = UtilityService.GetAppSetting("LoadBalancer:HealthCheckURL", "/load-balancer-health-check");

		int ForwardingTimeout { get; } = Int32.TryParse(UtilityService.GetAppSetting("SRP:ForwardingTimeout", "90"), out var timeout) && timeout > 0 ? timeout : 90;

		internal static Dictionary<string, Map> RedirectMaps { get; } = new Dictionary<string, Map>(StringComparer.OrdinalIgnoreCase);

		internal static Dictionary<string, Map> ForwardMaps { get; } = new Dictionary<string, Map>(StringComparer.OrdinalIgnoreCase);

		internal static Dictionary<string, Map> StaticMaps { get; } = new Dictionary<string, Map>(StringComparer.OrdinalIgnoreCase);
		#endregion

		public Handler(RequestDelegate _)
		{
			if (ConfigurationManager.GetSection(UtilityService.GetAppSetting("Section:Maps", "net.vieapps.services.srp.maps")) is AppConfigurationSectionHandler config)
				this.Prepare(config);

			Global.Logger.LogInformation("Settings:" + "\r\n" +
					$"=> Redirect to none WWW: {this.RedirectToNoneWWW}" + "\r\n" +
					$"=> Redirect to HTTPs: {this.RedirectToHTTPS}" + "\r\n" +
					$"=> Default directory: {this.DefaultDirectory}" + "\r\n" +
					$"=> Default file: {this.DefaultFile}" + "\r\n" +
					$"=> Redirect maps: {(Handler.RedirectMaps.Count < 1 ? "None" : $"\r\n\t+ {Handler.RedirectMaps.Select(kvp => $"{kvp.Key} => {kvp.Value.RedirectTo}" + (kvp.Value.Parameters.Count < 1 ? "" : "\r\n\t> Parameters:\r\n\t> > " + kvp.Value.Parameters.Select(p => $"{p.Name} -> {p.Attribute} [{p.Default}]").Join("\r\n\t> > "))).Join("\r\n\t+ ")}")}" + "\r\n" +
					$"=> Forward maps: {(Handler.ForwardMaps.Count < 1 ? "None" : $"\r\n\t+ {Handler.ForwardMaps.Select(kvp => $"{kvp.Key} => {kvp.Value.ForwardTo + $" ({kvp.Value.ForwardTokenName ?? "None"}/{kvp.Value.ForwardTokenValue ?? "None"})"}" + (kvp.Value.Parameters.Count < 1 ? "" : "\r\n\t> Parameters:\r\n\t> > " + kvp.Value.Parameters.Select(p => $"{p.Name} -> {p.Attribute} [{p.Default}]").Join("\r\n\t> > "))).Join("\r\n\t+ ")}")}" + "\r\n" +
					$"=> Static maps: {(Handler.StaticMaps.Count < 1 ? "None" : $"\r\n\t+ {Handler.StaticMaps.Select(kvp => $"{kvp.Key} => {kvp.Value.Directory + $" ({kvp.Value.RedirectToNoneWWW}/{kvp.Value.RedirectToHTTPS}/{kvp.Value.NotFound ?? "None"})"}" + (kvp.Value.Parameters.Count < 1 ? "" : "\r\n\t> Parameters:\r\n\t> > " + kvp.Value.Parameters.Select(p => $"{p.Name} -> {p.Attribute} [{p.Default}]").Join("\r\n\t> > "))).Join("\r\n\t+ ")}")}"
			);
		}

		void Prepare(AppConfigurationSectionHandler config)
		{
			// global settings
			this.RedirectToNoneWWW = "true".IsEquals(config.Section.Attributes["redirectToNoneWWW"]?.Value);
			this.RedirectToHTTPS = "true".IsEquals(config.Section.Attributes["redirectToHTTPS"]?.Value);
			this.DefaultDirectory = config.Section.Attributes["defaultDirectory"]?.Value ?? "apps";
			this.DefaultDirectory = Path.IsPathRooted(this.DefaultDirectory) ? this.DefaultDirectory : Path.Combine(Global.RootPath, this.DefaultDirectory);
			this.DefaultFile = config.Section.Attributes["defaultFile"]?.Value ?? "index.html";

			// individual settings
			if (config.Section.SelectNodes("map") is XmlNodeList maps)
				maps.ToList()
				.Where(info => !string.IsNullOrWhiteSpace(info.Attributes["host"]?.Value))
				.Select(info =>
				{
					var map = new Map
					{
						Host = info.Attributes["host"].Value,
						RedirectTo = info.Attributes["redirectTo"]?.Value,
						ForwardTo = info.Attributes["forwardTo"]?.Value,
						ForwardTokenName = info.Attributes["forwardTokenName"]?.Value,
						ForwardTokenValue = info.Attributes["forwardTokenValue"]?.Value,
						Directory = info.Attributes["directory"]?.Value,
						NotFound = info.Attributes["notFound"]?.Value,
						RedirectToNoneWWW = string.IsNullOrWhiteSpace(info.Attributes["redirectToNoneWWW"]?.Value) ? this.RedirectToNoneWWW : "true".IsEquals(info.Attributes["redirectToNoneWWW"]?.Value),
						RedirectToHTTPS = string.IsNullOrWhiteSpace(info.Attributes["redirectToHTTPS"]?.Value) ? this.RedirectToHTTPS : "true".IsEquals(info.Attributes["redirectToHTTPS"].Value),
						RedirectPermanently = !"false".IsEquals(info.Attributes["redirectPermanently"]?.Value)
					};
					info.ChildNodes?.ToList().ForEach(param =>
					{
						var name = param.Attributes["name"]?.Value;
						if (!string.IsNullOrWhiteSpace(name) && map.Parameters.FindIndex(p => p.Name.IsEquals(name)) < 0)
							map.Parameters.Add(new MapParameter
							{
								Name = name,
								Attribute = param.Attributes["attribute"]?.Value,
								Default = param.Attributes["default"]?.Value
							});
					});
					return map;
				})
				.Where(map => !string.IsNullOrWhiteSpace(map.RedirectTo) || !string.IsNullOrWhiteSpace(map.ForwardTo) || !string.IsNullOrWhiteSpace(map.Directory))
				.ForEach(map =>
				{
					if (!string.IsNullOrWhiteSpace(map.RedirectTo))
					{
						map.RedirectTo = map.RedirectTo.Trim();
						while (map.RedirectTo.EndsWith("/"))
							map.RedirectTo = map.RedirectTo.Left(map.RedirectTo.Length - 1);
						if (!map.RedirectTo.IsStartsWith("http://") && !map.RedirectTo.IsStartsWith("https://"))
							map.RedirectTo = "https://" + map.RedirectTo;
						map.Host.Trim().ToLower().ToArray("|", true).ForEach(host => Handler.RedirectMaps[host] = map.Clone(m => m.Host = host));
					}
					else if (!string.IsNullOrWhiteSpace(map.ForwardTo))
					{
						map.ForwardTo = map.ForwardTo.Trim();
						while (map.ForwardTo.EndsWith("/"))
							map.ForwardTo = map.ForwardTo.Left(map.ForwardTo.Length - 1);
						if (!map.ForwardTo.IsStartsWith("http://") && !map.ForwardTo.IsStartsWith("https://"))
							map.ForwardTo = "https://" + map.ForwardTo;
						map.Host.Trim().ToLower().ToArray("|", true).ForEach(host => Handler.ForwardMaps[host] = map.Clone(m => m.Host = host));
					}
					else
					{
						if (map.Directory.IndexOf(Path.DirectorySeparatorChar) < 0)
							map.Directory = Path.Combine(this.DefaultDirectory, map.Directory);
						map.Directory = Directory.Exists(map.Directory) ? map.Directory : Path.Combine(this.DefaultDirectory, map.Directory);
						map.Host.Trim().ToLower().ToArray("|", true).ForEach(host => Handler.StaticMaps[host] = map.Clone(m => m.Host = host));
					}
				});
		}

		public async Task Invoke(HttpContext context)
		{
			// CORS options
			if (context.Request.Method.IsEquals("OPTIONS"))
				context.SetResponseHeaders((int)HttpStatusCode.OK, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
				{
					["Access-Control-Allow-Origin"] = "*",
					["Access-Control-Allow-Methods"] = "*",
					["Access-Control-Allow-Headers"] = "*"
				});

			// process request
			else
			{
				// prepare
				var requestPath = context.Request.Path.Value;

				// health check
				if (requestPath.IsEquals(this.LoadBalancerHealthCheckURL))
					await context.WriteAsync("OK", "text/plain", null, 0, null, TimeSpan.Zero, null, Global.CancellationTokenSource.Token).ConfigureAwait(false);

				// maps
				else if (requestPath.IsEquals("/_maps"))
				{
					if ("true".IsEquals(UtilityService.GetAppSetting("SRP:AllowMaps", "true")))
					{
						var maps = Handler.RedirectMaps.Values.Select(map => map.ToJson())
							.Concat(Handler.ForwardMaps.Values.Select(map => map.ToJson()))
							.Concat(Handler.StaticMaps.Values.Select(map => map.ToJson()))
							.ToJArray();
						var token = context.GetQueryParameter("token");
						if (string.IsNullOrWhiteSpace(token) || !token.IsEquals(UtilityService.GetAppSetting("SRP:Token")))
							maps.ForEach(map => map["RedirectTo"] = map["ForwardTo"] = map["ForwardTokenName"] = map["ForwardTokenValue"] = map["Directory"] = "*****");

						using var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted);
						await context.WriteAsync(maps, cts.Token).ConfigureAwait(false);
					}
					else
						context.ShowError(404, $"Not Found [{context.GetUri()}]", "FileNotFoundException", context.GetCorrelationID());
				}

				// other requests
				else
				{
					var requestURI = context.GetRequestUri();
					if (Handler.RedirectMaps.Get(requestURI.Host, out var map))
					{
						var redirectURL = map.RedirectTo + requestURI.PathAndQuery + requestURI.Fragment;
						if (map.Parameters.Count > 0)
						{
							var parameter = map.Parameters.FirstOrDefault(param => param.Name.IsStartsWith("c:")
								? requestPath.IsContains(param.Name.Right(param.Name.Length - 2))
								: param.Name.IsStartsWith("e:")
									? requestPath.IsEndsWith(param.Name.Right(param.Name.Length - 2))
									: requestPath.IsStartsWith(param.Name.IsStartsWith("s:") ? param.Name.Right(param.Name.Length - 2) : param.Name)
								);
							var location = parameter?.Attribute ?? parameter?.Default;
							if (!string.IsNullOrWhiteSpace(location))
								redirectURL = location.IsStartsWith("https://") || location.IsStartsWith("http://") ? location : map.RedirectTo + location + requestURI.Fragment;
						}
						redirectURL = map.RedirectToHTTPS ? redirectURL.Replace("http://", "https://") : redirectURL;
						redirectURL = map.RedirectToNoneWWW ? redirectURL.Replace("://www.", "://") : redirectURL;
						if (Global.IsDebugLogEnabled || context.ContainsKey("x-logs"))
							await context.WriteLogsAsync("Http.Redirects", $"Redirect to other location ({requestURI} => {redirectURL})").ConfigureAwait(false);
						context.Redirect(redirectURL, map.RedirectPermanently);
					}
					else
						await (Handler.ForwardMaps.ContainsKey(requestURI.Host) || (!Handler.StaticMaps.ContainsKey(requestURI.Host) && Handler.ForwardMaps.ContainsKey("*")) ? this.ProcessForwardRequestAsync(context) : this.ProcessStaticRequestAsync(context)).ConfigureAwait(false);
				}
			}
		}

		#region Process forwarding requests
		async Task ProcessForwardRequestAsync(HttpContext context)
		{
			// get map info
			context.SetItem("PipelineStopwatch", Stopwatch.StartNew());
			var requestUri = context.GetRequestUri();
			Handler.ForwardMaps.Get(requestUri.Host, out var map);
			if (map == null)
				Handler.ForwardMaps.Get("*", out map);

			// redirect
			var redirectToHttps = (map != null ? map.RedirectToHTTPS : this.RedirectToHTTPS) && !requestUri.Scheme.IsEquals("https");
			var redirectToNoneWWW = (map != null ? map.RedirectToNoneWWW : this.RedirectToNoneWWW) && requestUri.Host.StartsWith("www.");
			if (redirectToHttps || redirectToNoneWWW)
			{
				var url = $"{requestUri}";
				url = redirectToHttps ? url.Replace("http://", "https://") : url;
				url = redirectToNoneWWW ? url.Replace("://www.", "://") : url;
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("Http.Forwards", $"Redirect to HTTPS/None WWW ({requestUri} => {url})");
				context.Redirect(url, true);
				return;
			}

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitStartingLogAsync().ConfigureAwait(false);

			// prepare
			var forwardingToken = !string.IsNullOrWhiteSpace(map.ForwardTokenName) && !context.Request.Query.ContainsKey(map.ForwardTokenName) ? $"{map.ForwardTokenName}={map.ForwardTokenValue.UrlEncode()}" : "";
			var uri = new Uri(map.ForwardTo + requestUri.PathAndQuery + (string.IsNullOrWhiteSpace(forwardingToken) ? "" : $"{(requestUri.PathAndQuery.IndexOf("?") > -1 ? "&" : "?")}{forwardingToken}") + requestUri.Fragment);

			var method = context.Request.Method;
			var headers = context.Request.Headers.ToDictionary().Copy(context.Request.Headers.Keys.Where(key => key.IsStartsWith("x-forwarded") || key.IsStartsWith("x-original")).Concat(["Host", "Connection"]), dictionary => dictionary["X-SRP-Host"] = $"{requestUri.Host}{(requestUri.Port != 80 && requestUri.Port != 443 ? $":{requestUri.Port}" : "")}");

			// forward the request
			if (Global.IsDebugLogEnabled)
			{
				var userAgent = context.GetUserAgent();
				var referer = context.GetReferUrl();
				await context.WriteLogsAsync("Http.Forwards", $"Forwarding request is starting [{method}: {requestUri} => {uri}] {context.Request.Protocol}\r\n- IP: {context.Connection.RemoteIpAddress}{(string.IsNullOrWhiteSpace(userAgent) ? "" : $"\r\n- Agent: {userAgent}")}{(string.IsNullOrWhiteSpace(referer) ? "" : $"\r\n- Referer: {referer}")}" + (Global.IsDebugLogEnabled ? $"\r\n- Headers:\r\n\t{headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}" : "")).ConfigureAwait(false);
			}

			var statusCode = HttpStatusCode.OK;
			try
			{
				using var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted);
				using var response = await uri.SendHttpRequestAsync(method, headers, method.IsEquals("POST") || method.IsEquals("PUT") || method.IsEquals("PATCH") ? await context.ReadAsync(cts.Token).ConfigureAwait(false) : null, this.ForwardingTimeout, cts.Token).ConfigureAwait(false);
				statusCode = response.StatusCode;
				headers = response.GetHeaders(["Connection", "Content-Encoding", "Transfer-Encoding", "Set-Cookie"], dictionary => dictionary["Server"] = AspNetCoreUtilityService.ServerName);
				context.SetResponseHeaders((int)statusCode, headers);
				context.AppendCookies(response.GetCookies(cookie => cookie.Domain = string.IsNullOrWhiteSpace(cookie.Domain) || cookie.Domain.IsEquals(uri.Host) ? requestUri.Host : cookie.Domain));
				await response.CopyToAsync(context.Response.Body, cts.Token).ConfigureAwait(false);
			}
			catch (RemoteServerException ex)
			{
				statusCode = ex.StatusCode;
				headers = ex.Headers.Copy(["Connection", "Content-Encoding", "Transfer-Encoding", "Set-Cookie"]);
				if (ex.IsSuccessStatusCode)
				{
					context.SetResponseHeaders((int)statusCode, headers);
					context.AppendCookies(ex.Headers.TryGetValue("Set-Cookie", out var value) && !string.IsNullOrWhiteSpace(value) ? value.ToList().GetCookies(uri.Host, cookie => cookie.Domain = string.IsNullOrWhiteSpace(cookie.Domain) || cookie.Domain.IsEquals(uri.Host) ? requestUri.Host : cookie.Domain) : new CookieCollection());
				}
				else
					context.ShowError((int)statusCode, ex.Body ?? context.GetHttpStatusCodeBody((int)statusCode, ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex.GetStack(), Global.IsDebugLogEnabled), headers);
			}
			catch (Exception ex)
			{
				statusCode = (HttpStatusCode)ex.GetHttpStatusCode();
				context.ShowError((int)statusCode, context.GetHttpStatusCodeBody((int)statusCode, ex.Message, ex.GetTypeName(true), context.GetCorrelationID(), ex.GetStack(), Global.IsDebugLogEnabled));
			}
			finally
			{
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("Http.Forwards", $"Forwarding request is completed\r\n- Status: {statusCode}\r\n- Headers:\r\n\t{headers.ToString("\r\n\t", kvp => $"{kvp.Key}: {kvp.Value}")}").ConfigureAwait(false);
			}

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitFinishingLogAsync().ConfigureAwait(false);
		}
		#endregion

		#region Process static file requests
		async Task ProcessStaticRequestAsync(HttpContext context)
		{
			// prepare
			context.SetItem("PipelineStopwatch", Stopwatch.StartNew());
			var requestUri = context.GetRequestUri();

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitStartingLogAsync().ConfigureAwait(false);

			// only allow GET method
			if (!context.Request.Method.IsEquals("GET"))
				context.ShowError((int)HttpStatusCode.MethodNotAllowed, $"Method {context.Request.Method} is not allowed", "MethodNotAllowedException", context.GetCorrelationID());

			else
			{
				// process request of static files
				if (Global.StaticSegments.Contains(requestUri.GetRequestPathSegments().First()))
					await context.ProcessStaticFileRequestAsync().ConfigureAwait(false);

				// process request of other files
				else
					try
					{
						var fileInfo = await this.ProcessFileRequestAsync(context).ConfigureAwait(false);
						if (fileInfo != null && Global.IsDebugLogEnabled)
							await context.WriteLogsAsync("Http.Statics", $"Success response ({fileInfo.FullName})").ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						await context.WriteLogsAsync("Http.Statics", $"Failure response [{requestUri}]", ex).ConfigureAwait(false);
						context.ShowError(ex.GetHttpStatusCode(), ex.Message, ex.GetType().GetTypeName(true), context.GetCorrelationID(), ex, Global.IsDebugLogEnabled);
					}
			}

			if (Global.IsVisitLogEnabled)
				await context.WriteVisitFinishingLogAsync().ConfigureAwait(false);
		}

		async Task<FileInfo> ProcessFileRequestAsync(HttpContext context)
		{
			// prepare
			var requestUri = context.GetRequestUri();
			Handler.StaticMaps.Get(requestUri.Host, out var map);

			// redirect
			var redirectToHttps = (map != null ? map.RedirectToHTTPS : this.RedirectToHTTPS) && !requestUri.Scheme.IsEquals("https");
			var redirectToNoneWWW = (map != null ? map.RedirectToNoneWWW : this.RedirectToNoneWWW) && requestUri.Host.StartsWith("www.");
			if (redirectToHttps || redirectToNoneWWW)
			{
				var url = $"{requestUri}";
				url = redirectToHttps ? url.Replace("http://", "https://") : url;
				url = redirectToNoneWWW ? url.Replace("://www.", "://") : url;
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("Http.Redirects", $"Redirect to HTTPS/None WWW ({requestUri} => {url})");
				context.Redirect(url, true);
				return null;
			}

			// prepare file info
			FileInfo fileInfo = null;
			var filePath = $"{map?.Directory ?? this.DefaultDirectory}/{requestUri.GetRequestPathSegments().Join("/")}".Replace(@"\", "/").Replace("//", "/").Replace('/', Path.DirectorySeparatorChar).Replace("%20", " ").Replace("+", " ");
			filePath += filePath.EndsWith(Path.DirectorySeparatorChar) ? this.DefaultFile : "";

			// check to reduce traffic
			var eTag = $"vieapps#{requestUri.AbsoluteUri.ToLower().GenerateUUID()}";
			if (eTag.IsEquals(context.GetHeaderParameter("If-None-Match")))
			{
				var isNotModified = true;
				var lastModifed = DateTime.Now.ToUnixTimestamp();
				if (context.GetHeaderParameter("If-Modified-Since") != null)
				{
					fileInfo = new FileInfo(filePath);
					if (!fileInfo.Exists && File.Exists(Path.Combine(filePath, $"{Path.DirectorySeparatorChar}", this.DefaultFile)))
						fileInfo = new FileInfo(Path.Combine(filePath, $"{Path.DirectorySeparatorChar}", this.DefaultFile));
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
						await context.WriteLogsAsync("Http.Statics", $"Success response with status code 304 to reduce traffic ({filePath})").ConfigureAwait(false);
					return fileInfo;
				}
			}

			// check existed
			fileInfo = fileInfo ?? new FileInfo(filePath);
			if (!fileInfo.Exists)
			{
				if (!string.IsNullOrWhiteSpace(map?.NotFound))
					fileInfo = new FileInfo(Path.Combine(Path.IsPathRooted(map.Directory) ? map.Directory : Path.Combine(this.DefaultDirectory, map.Directory), map.NotFound));
				else if (File.Exists(Path.Combine(filePath, $"{Path.DirectorySeparatorChar}", this.DefaultFile)))
					fileInfo = new FileInfo(Path.Combine(filePath, $"{Path.DirectorySeparatorChar}", this.DefaultFile));
			}

			if (!fileInfo.Exists)
			{
				if (Global.IsDebugLogEnabled)
					await context.WriteLogsAsync("Http.Statics", $"Requested file is not found [{requestUri}] => [{fileInfo.FullName}]").ConfigureAwait(false);
				throw new FileNotFoundException($"Not Found [{requestUri}]");
			}

			// prepare
			using var cts = CancellationTokenSource.CreateLinkedTokenSource(Global.CancellationToken, context.RequestAborted);
			var mimeType = fileInfo.GetMimeType();
			var headers = new Dictionary<string, string>
			{
				{ "Content-Type", mimeType + (mimeType.IsStartsWith("text/") || mimeType.IsEndsWith("/json") || mimeType.IsEndsWith("/javascript") ? "; charset=utf-8" : "") },
				{ "ETag", eTag },
				{ "Last-Modified", fileInfo.LastWriteTime.ToHttpString() },
				{ "Cache-Control", "public" },
				{ "Expires", DateTime.Now.AddMinutes(13).ToHttpString() },
				{ "X-Correlation-ID", context.GetCorrelationID() },
				{ "X-Node", Global.NodeID }
			};

			// write HTML files
			if (mimeType.IsStartsWith("text/") && fileInfo.Extension.IsStartsWith(".htm") && map.Parameters.Count > 0)
			{
				// prepare social tags
				var parameters = new List<(string Name, string Attribute)>();

				var requestInfo = context.GetQueryParameter("ngx");
				if (!string.IsNullOrWhiteSpace(requestInfo) && !string.IsNullOrWhiteSpace(context.GetQueryParameter(requestInfo)))
				{
					try
					{
						requestInfo = context.GetQueryParameter(requestInfo).Url64Decode();
						requestInfo = QueryHelpers.ParseQuery(requestInfo.Right(requestInfo.Length - requestInfo.IndexOf("?")))["x-request"].ToString().Url64Decode();
					}
					catch (Exception ex)
					{
						requestInfo = null;
						await context.WriteLogsAsync("Http.Statics", $"Error occurred while parsing parameters => {ex.Message}", ex).ConfigureAwait(false);
					}
				}
				else
				{
					requestInfo = context.GetQueryParameter("x-request");
					if (!string.IsNullOrWhiteSpace(requestInfo))
						try
						{
							requestInfo = requestInfo.Url64Decode();
						}
						catch (Exception ex)
						{
							requestInfo = null;
							await context.WriteLogsAsync("Http.Statics", $"Error occurred while parsing parameters => {ex.Message}", ex).ConfigureAwait(false);
						}
				}

				if (!string.IsNullOrWhiteSpace(requestInfo))
					try
					{
						var serviceInfo = JObject.Parse(requestInfo);
						var serviceObject = await context.CallServiceAsync(new RequestInfo(context.GetSession(), serviceInfo.Get<string>("Service"), serviceInfo.Get<string>("Object"), "GET")
						{
							Query = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
							{
								{ "object-identity", serviceInfo.Get<string>("ID") }
							},
							CorrelationID = context.GetCorrelationID()
						}, cts.Token).ConfigureAwait(false);

						map.Parameters.ForEach(parameter => parameters.Add(new (parameter.Name, string.IsNullOrWhiteSpace(parameter.Attribute) ? parameter.Default ?? "" : serviceObject.Get<string>(parameter.Attribute) ?? parameter.Default ?? "")));
						if (Global.IsDebugLogEnabled)
							await context.WriteLogsAsync("Http.Statics", $"Parameters of static HTML file:\r\n\t+ {parameters.Select(parameter => $"{parameter.Name}: {parameter.Attribute}").Join("\r\n\t+ ")}").ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						map.Parameters.ForEach(parameter => parameters.Add(new (parameter.Name, parameter.Default ?? "")));
						await context.WriteLogsAsync("Http.Statics", $"Error occurred while processing parameters => {ex.Message}", ex).ConfigureAwait(false);
					}
				else
					map.Parameters.ForEach(parameter => parameters.Add(new (parameter.Name, parameter.Default ?? "")));

				// get & normalize content
				var html = await fileInfo.ReadAsTextAsync(cts.Token).ConfigureAwait(false);
				if (parameters.Count > 0)
					parameters.ForEach(parameter => html = html.Replace(StringComparison.OrdinalIgnoreCase, "{{" + parameter.Name + "}}", parameter.Attribute));

				// write to response
				await context.WriteAsync(html, headers, cts.Token).ConfigureAwait(false);
			}

			// other files
			else
				await context.SendFileAsync(fileInfo, headers, cts.Token).ConfigureAwait(false);

			return fileInfo;
		}
		#endregion

		#region API Gateway Router
		internal static void Connect(int waitingTimes = 6789)
		{
			Global.Logger.LogInformation($"Attempting to connect to API Gateway Router [{new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}]");
			Global.Connect
			(
				(sender, arguments) =>
				{
					Global.PrimaryInterCommunicateMessageUpdater?.Dispose();
					Global.PrimaryInterCommunicateMessageUpdater = Router.IncomingChannel.Subscribe<CommunicateMessage>(
						"messages.services.srp",
						message => Global.NodeID.IsEquals(message.ExcludedNodeID) ? Task.CompletedTask : Handler.ProcessInterCommunicateMessageAsync(message),
						exception => Global.WriteLogsAsync(Global.Logger, "Http.Updates", $"Error occurred while fetching an inter-communicate message: {exception.Message}", exception)
					);
					Global.SecondaryInterCommunicateMessageUpdater?.Dispose();
					Global.SecondaryInterCommunicateMessageUpdater = Router.IncomingChannel.Subscribe<CommunicateMessage>(
						"messages.services.apigateway",
						message => message.Type.IsEquals("Service#RequestInfo") ? Global.SendServiceInfoAsync() : Task.CompletedTask,
						exception => Global.WriteLogsAsync(Global.Logger, "Http.Updates", $"Error occurred while fetching an inter-communicate message of API Gateway: {exception.Message}", exception)
					);
				},
				(sender, arguments) => Task.Run(async () => await Global.RegisterServiceAsync().ConfigureAwait(false)).ContinueWith(async _ =>
				{
					while (Router.IncomingChannel == null)
						await Task.Delay(UtilityService.GetRandomNumber(234, 567), Global.CancellationTokenSource.Token).ConfigureAwait(false);
					await Task.WhenAll
					(
						Handler.RedirectMaps.Select(kvp => new CommunicateMessage(Global.ServiceName)
						{
							Type = "Update#Redirect",
							Data = kvp.Value.ToJson()
						})
						.Select(message => message.PublishAsync(Global.Logger, "Http.Updates"))
						.Concat(Handler.ForwardMaps.Select(kvp => new CommunicateMessage(Global.ServiceName)
						{
							Type = "Update#Forward",
							Data = kvp.Value.ToJson()
						}).Select(message => message.PublishAsync(Global.Logger, "Http.Updates")))
						.ToList()
					).ConfigureAwait(false);
				}, TaskContinuationOptions.OnlyOnRanToCompletion).ConfigureAwait(false),
				waitingTimes,
				exception => Global.Logger.LogError($"Cannot connect to API Gateway Router in period of times => {exception.Message}", exception),
				exception => Global.Logger.LogError($"Error occurred while connecting to API Gateway Router => {exception.Message}", exception)
			);
		}

		internal static void Disconnect()
		{
			Global.UnregisterService();
			Global.Disconnect();
		}

		async static Task ProcessInterCommunicateMessageAsync(CommunicateMessage message)
		{
			if ("Update#Redirect".IsEquals(message.Type))
			{
				var map = message.Data?.Copy<Map>();
				if (map != null)
				{
					Handler.RedirectMaps[map.Host] = map;
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(Global.Logger, "Http.Updates", $"Update redirect map successful => {map.ToJson()}", null).ConfigureAwait(false);
				}
			}
			else if ("Update#Forward".IsEquals(message.Type))
			{
				var map = message.Data?.Copy<Map>();
				if (map != null)
				{
					Handler.ForwardMaps[map.Host] = map;
					if (Global.IsDebugLogEnabled)
						await Global.WriteLogsAsync(Global.Logger, "Http.Updates", $"Update forward map successful => {map.ToJson()}", null).ConfigureAwait(false);
				}
			}
		}
		#endregion

	}

	#region Map & Parameter
	public class Map
	{
		public Map() { }

		public string Host { get; set; } = "";

		public string RedirectTo { get; set; }

		public string ForwardTo { get; set; }

		public string ForwardTokenName { get; set; }

		public string ForwardTokenValue { get; set; }

		public string Directory { get; set; } = "";

		public string NotFound { get; set; }

		public bool RedirectToNoneWWW { get; set; } = false;

		public bool RedirectToHTTPS { get; set; } = false;

		public bool RedirectPermanently { get; set; } = true;

		public List<MapParameter> Parameters { get; set; } = [];
	}

	public class MapParameter
	{
		public MapParameter() { }

		public string Name { get; set; } = "";

		public string Attribute { get; set; }

		public string Default { get; set; }
	}

	internal static class HandlerExtensions
	{
		public static bool Get(this Dictionary<string, Map> maps, string host, out Map map)
			=> maps.TryGetValue(host, out map) || (host.IsStartsWith("www.") && maps.TryGetValue(host.Right(host.Length - 4), out map));
	}
	#endregion

}