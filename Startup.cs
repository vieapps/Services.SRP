﻿#region Related components
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
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Hosting;
#if !NETCOREAPP2_1
using Microsoft.Extensions.Hosting;
#endif
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
			=> WebHost.CreateDefaultBuilder(args).Run<Startup>(args, 8028);

		public Startup(IConfiguration configuration)
			=> this.Configuration = configuration;

		public IConfiguration Configuration { get; }

		LogLevel LogLevel => this.Configuration.GetAppSetting("Logging/LogLevel/Default", UtilityService.GetAppSetting("Logs:Level", "Information")).TryToEnum(out LogLevel logLevel) ? logLevel : LogLevel.Information;

		public void ConfigureServices(IServiceCollection services)
		{
			services
				.AddResponseCompression(options => options.EnableForHttps = true)
				.AddLogging(builder => builder.SetMinimumLevel(this.LogLevel))
				.AddCache(options => this.Configuration.GetSection("Cache").Bind(options))
				.AddHttpContextAccessor();
		}

		public void Configure(
			IApplicationBuilder appBuilder,
#if !NETCOREAPP2_1
			IHostApplicationLifetime appLifetime,
			IWebHostEnvironment environment
#else
			IApplicationLifetime appLifetime,
			IHostingEnvironment environment
#endif
		)
		{
			// environments
			var stopwatch = Stopwatch.StartNew();
			Console.OutputEncoding = Encoding.UTF8;
			Global.ServiceName = "SRP";
			AspNetCoreUtilityService.ServerName = UtilityService.GetAppSetting("ServerName", "VIEApps NGX");

			JsonConvert.DefaultSettings = () => new JsonSerializerSettings
			{
				Formatting = Formatting.None,
				ReferenceLoopHandling = ReferenceLoopHandling.Ignore,
				DateTimeZoneHandling = DateTimeZoneHandling.Local
			};

			var loggerFactory = appBuilder.ApplicationServices.GetService<ILoggerFactory>();
			var logPath = UtilityService.GetAppSetting("Path:Logs");
			if (!string.IsNullOrWhiteSpace(logPath) && Directory.Exists(logPath))
			{
				logPath = Path.Combine(logPath, "{Hour}" + $"_{Global.ServiceName.ToLower()}.http.all.txt");
				loggerFactory.AddFile(logPath, this.LogLevel);
			}
			else
				logPath = null;

			// setup the service
			Logger.AssignLoggerFactory(loggerFactory);
			Global.Logger = loggerFactory.CreateLogger<Startup>();

			Global.ServiceProvider = appBuilder.ApplicationServices;
			Global.RootPath = environment.ContentRootPath;

			Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is starting");
			Global.Logger.LogInformation($"Version: {typeof(Startup).Assembly.GetVersion()}");
#if DEBUG
			Global.Logger.LogInformation($"Working mode: DEBUG ({(environment.IsDevelopment() ? "Development" : "Production")})");
#else
			Global.Logger.LogInformation($"Working mode: RELEASE ({(environment.IsDevelopment() ? "Development" : "Production")})");
#endif
			Global.Logger.LogInformation($"Environment:\r\n\t- User: {Environment.UserName.ToLower()} @ {Environment.MachineName.ToLower()}\r\n\t- Platform: {RuntimeInformation.FrameworkDescription} @ {(RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "Windows" : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "macOS")} {RuntimeInformation.OSArchitecture} ({(RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "Macintosh; Intel Mac OS X; " : "")}{RuntimeInformation.OSDescription.Trim()})");
			Global.Logger.LogInformation($"Service URIs:\r\n\t- Round robin: services.{Global.ServiceName.ToLower()}.http\r\n\t- Single (unique): services.{Extensions.GetUniqueName(Global.ServiceName + ".http")}");

			// connect to API Gateway Router
			Handler.Connect();

			// setup middlewares
			appBuilder
				.UseForwardedHeaders(Global.GetForwardedHeadersOptions())
				.UseCache()
				.UseStatusCodeHandler()
				.UseResponseCompression()
				.UseMiddleware<Handler>();

			// setup the caching storage
			Global.Cache = appBuilder.ApplicationServices.GetService<ICache>();

			// on started
			appLifetime.ApplicationStarted.Register(() =>
			{
				Global.Logger.LogInformation($"API Gateway Router: {new Uri(Router.GetRouterStrInfo()).GetResolvedURI()}");
				Global.Logger.LogInformation($"API Gateway HTTP service: {UtilityService.GetAppSetting("HttpUri:APIs", "None")}");
				Global.Logger.LogInformation($"Files HTTP service: {UtilityService.GetAppSetting("HttpUri:Files", "None")}");
				Global.Logger.LogInformation($"Portals HTTP service: {UtilityService.GetAppSetting("HttpUri:Portals", "None")}");
				Global.Logger.LogInformation($"Passports HTTP service: {UtilityService.GetAppSetting("HttpUri:Passports", "None")}");
				Global.Logger.LogInformation($"Root (base) directory: {Global.RootPath}");
				Global.Logger.LogInformation($"Temporary directory: {UtilityService.GetAppSetting("Path:Temp", "None")}");
				Global.Logger.LogInformation($"Static files directory: {UtilityService.GetAppSetting("Path:StaticFiles", "None")}");
				Global.Logger.LogInformation($"Static segments: {Global.StaticSegments.ToString(", ")}");
				Global.Logger.LogInformation($"Logging level: {this.LogLevel} - Local rolling log files is {(string.IsNullOrWhiteSpace(logPath) ? "disabled" : $"enabled => {logPath}")}");
				Global.Logger.LogInformation($"Show debugs: {Global.IsDebugLogEnabled} - Show results: {Global.IsDebugResultsEnabled} - Show stacks: {Global.IsDebugStacksEnabled}");

				stopwatch.Stop();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service is started - PID: {Process.GetCurrentProcess().Id} - Execution times: {stopwatch.GetElapsedTimes()}");
				Global.Logger = loggerFactory.CreateLogger<Handler>();
			});

			// on stopping
			appLifetime.ApplicationStopping.Register(() =>
			{
				Global.Logger = loggerFactory.CreateLogger<Startup>();
				Handler.Disconnect();
				Global.CancellationTokenSource.Cancel();
			});

			// on stopped
			appLifetime.ApplicationStopped.Register(() =>
			{
				Global.CancellationTokenSource.Dispose();
				Global.Logger.LogInformation($"The {Global.ServiceName} HTTP service was stopped");
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