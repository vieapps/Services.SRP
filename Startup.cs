#region Related components
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Caching.Distributed;

using Newtonsoft.Json;

using net.vieapps.Components.Utility;
using net.vieapps.Components.Caching;
#endregion

namespace net.vieapps.Services.SRP
{
	public class Startup
	{
		public static void Main(string[] args)
		{
			WebHost.CreateDefaultBuilder(args)
				.CaptureStartupErrors(true)
				.UseStartup<Startup>()
				.UseKestrel(options => options.AddServerHeader = false)
				.UseUrls(args.FirstOrDefault(a => a.IsStartsWith("/ListenURI:"))?.Replace("/ListenURI:", "", StringComparison.OrdinalIgnoreCase) ?? UtilityService.GetAppSetting("HttpUri:Listen", "http://0.0.0.0:8028").Trim())
				.Build()
				.Run();
		}

		public Startup(IConfiguration configuration) => this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		LogLevel LogLevel => this.Configuration.GetAppSetting("Logging/LogLevel/Default", "Information").ToEnum<LogLevel>();

		public void ConfigureServices(IServiceCollection services) => services.AddResponseCompression(options => options.EnableForHttps = true).AddLogging(builder => builder.SetMinimumLevel(this.LogLevel)).AddHttpContextAccessor();

		public void Configure(IApplicationBuilder app, IApplicationLifetime appLifetime, IHostingEnvironment environment)
		{
			// settings
			var stopwatch = Stopwatch.StartNew();
			Global.ServiceName = "SRP";
			Console.OutputEncoding = Encoding.UTF8;

			var loggerFactory = app.ApplicationServices.GetService<ILoggerFactory>();
			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Date}" + $"_{Global.ServiceName.ToLower()}.http.txt");
				loggerFactory.AddFile(logPath, this.LogLevel);
			}
			else
				logPath = null;

			Logger.AssignLoggerFactory(loggerFactory);
			Global.Logger = loggerFactory.CreateLogger<Startup>();

			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");
			Global.Logger.LogInformation($"Version: {typeof(Startup).Assembly.GetVersion()}");
			Global.Logger.LogInformation($"Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
#if DEBUG
			Global.Logger.LogInformation($"Working mode: DEBUG ({(environment.IsDevelopment() ? "Development" : "Production")})");
#else
			Global.Logger.LogInformation($"Working mode: RELEASE ({(environment.IsDevelopment() ? "Development" : "Production")})");
#endif

			Global.ServiceProvider = app.ApplicationServices;
			Global.RootPath = environment.ContentRootPath;

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			// reverse proxies
			var forwardedHeadersOptions = new ForwardedHeadersOptions
			{
				ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
			};
			var knownProxies = UtilityService.GetAppSetting("ProxyIPs")?.ToList().Select(ip => IPAddress.Parse(ip)).ToList();
			if (knownProxies != null)
			{
				forwardedHeadersOptions.RequireHeaderSymmetry = false;
				forwardedHeadersOptions.ForwardLimit = null;
				knownProxies.ForEach(ip => forwardedHeadersOptions.KnownProxies.Add(ip));
			}

			// setup middlewares
			app.UseForwardedHeaders(forwardedHeadersOptions).UseStatusCodeHandler();
			app.UseResponseCompression().UseMiddleware<Handler>();

			// connect to WAMP router
			Handler.OpenWAMPChannels();

			// on started
			appLifetime.ApplicationStarted.Register(() =>
			{
				Global.Logger.LogInformation($"Listening URI: {UtilityService.GetAppSetting("HttpUri:Listen", "http://0.0.0.0:8028")}");
				Global.Logger.LogInformation($"WAMP router URI: {WAMPConnections.GetRouterStrInfo()}");
				Global.Logger.LogInformation($"Root path: {Global.RootPath}");
				Global.Logger.LogInformation($"Default logging level: {this.LogLevel} [ASP.NET Core always set logging level by value of appsettings.json]");
				Global.Logger.LogInformation($"Logging folder: {(logPath == null ? "None" : Path.GetDirectoryName(logPath))}");
				Global.Logger.LogInformation($"Rolling log files is {(logPath == null ? "disabled" : $"enabled - Path format: {logPath}")}");
				Global.Logger.LogInformation($"Static files path: {UtilityService.GetAppSetting("Path:StaticFiles", "None")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();
				Global.InterCommunicateMessageUpdater?.Dispose();
				WAMPConnections.CloseChannels();
				Global.CancellationTokenSource.Cancel();
			});

			// on stopped
			appLifetime.ApplicationStopped.Register(() =>
			{
				Global.CancellationTokenSource.Dispose();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is stopped");
			});

			// don't terminate the process immediately, wait for the Main thread to exit gracefully
			Console.CancelKeyPress += (sender, args) =>
			{
				appLifetime.StopApplication();
				args.Cancel = true;
			};
		}
	}
}