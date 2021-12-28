using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Runtime.Versioning;
using System.Security.Principal;

namespace DnsSwitch
{
    [SupportedOSPlatform("windows")]
    class Program
    {
        private static bool _wizard;
        private static bool _quiet;
        private static bool _force;
        private static readonly string UserConfigFileLocation = AppDomain.CurrentDomain.BaseDirectory + "\\user-config.json";
        private const string BadIpValue = "BadValue";
        private const string First = "[First]";

        static int Main(string[] args)
        {
            var filteredArgs = args.Where(a => !a.StartsWith("-")).ToArray();
            var options = args.Where(a => a.StartsWith("-")).ToArray();
            
            _wizard = !filteredArgs.Any();
            _quiet = options.Contains("-q") || options.Contains("--quiet");
            _force = options.Contains("-f") || options.Contains("--force");

            if (options.Contains("-h") || options.Contains("--help"))
            {
                WriteHelp();
                return 0;
            }

            if (!CheckAdmin()) 
                return -1;

            var adapterIndex = -1;
            var input1 = BadIpValue;
            var input2 = BadIpValue;
            
            if (filteredArgs.Length > 0 && !ParseArgs(filteredArgs, ref adapterIndex, ref input1, ref input2, out var parseArgsReturnCode))
            {
                if (parseArgsReturnCode == 0) 
                    return parseArgsReturnCode;

                // Args didn't parse - first segment is not an index, it could be an operation or a configuration code.

                    var shouldReturn = ProcessOperations(filteredArgs, out var operationReturnCode);
                if (shouldReturn) 
                    return operationReturnCode;

                var configuration = GetConfig(filteredArgs[0]);
                if (configuration != null && configuration.Any())
                {
                    configuration[0] = GetAdapterIndex(configuration[0]).ToString();
                    if (!ParseArgs(configuration, ref adapterIndex, ref input1, ref input2, out var parseConfigReturnCode))
                    {
                        return parseConfigReturnCode;
                    }
                }
                else
                {
                    NetworkAdapterNotFound();
                    return parseArgsReturnCode;
                }
            }

            // quiet can't prompt - just fail
            if (_quiet && (adapterIndex == -1 || input1 == BadIpValue))
                return -1;

            if (adapterIndex == -1)
            {
                adapterIndex = CollectAdapterIndex();
                if (adapterIndex == -1)
                    return -1;
            }
            
            if (input1 == BadIpValue)
            {
                input1 = CollectIp("Address 1 (blank for automatic): ");
            }
            
            if (_wizard && !string.IsNullOrEmpty(input1) && input2 == BadIpValue)
            {
                input2 = CollectIp("Address 2 (blank for empty): ");
            }

            if (_wizard)
            {
                WriteLine("Provide a code to save this configuration (otherwise leave blank): ");
                var code = Console.ReadLine()?.Trim();
                if (!string.IsNullOrWhiteSpace(code))
                {
                    var description = GetAdapterDescription(adapterIndex);
                    if (!WriteCustomSetting(code, description, input1, input2))
                        return -1;
                }
            }

            if (adapterIndex > -1)
            {
                var response = SetDns(adapterIndex, new[] { input1, input2 }.Where(i => !string.IsNullOrEmpty(i) && i != BadIpValue && !i.Split(".").All(r => r == "0")).ToArray());
                WriteLine(response);   
            }
                
            return 0;
        }

        private static bool ProcessOperations(string[] filteredArgs, out int operationReturnCode)
        {
            operationReturnCode = 0;

            if ("add".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                if (!int.TryParse(filteredArgs[2], out var adapterIndex))
                {
                    operationReturnCode = -1;
                    return true;
                }

                var description = GetAdapterDescription(adapterIndex);
                if (description == null)
                {
                    operationReturnCode = -1;
                    return true;
                }

                var ip1 = ValidateIPv4(filteredArgs[3]) ? filteredArgs[3] : "auto";
                var ip2 = ValidateIPv4(filteredArgs[4]) ? filteredArgs[4] : "";
                if (!WriteCustomSetting(filteredArgs[1], description, ip1, ip2))
                {
                    operationReturnCode = -1;
                }

                return true;
            }

            if ("remove".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                RemoveConfig(filteredArgs[1]);
                return true;
            }

            if ("list".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase) || "ls".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                foreach (var s in ListConfig())
                {
                    WriteLine(s);
                }
                
                return true;
            }

            if ("nics".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                var adapters = GetAdapters();
                for (int i = 0; i < adapters.Length; i++)
                {
                    WriteLine($"{i}: {adapters[i]}");
                }
                
                return true;
            }

            if ("status".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                var adapters = GetAdapters(true);
                for (int i = 0; i < adapters.Length; i++)
                {
                    WriteLine($"{i}: {adapters[i]}");
                }
                
                return true;
            }

            if ("dns".Equals(filteredArgs[0], StringComparison.InvariantCultureIgnoreCase))
            {
                var ip = Dns.GetHostAddresses(filteredArgs[1]);
                if (ip == default(IPAddress[]) || ip.Length == 0)
                {
                    WriteLine($"Could not find `{filteredArgs[1]}`");
                    return false;
                }

                var index = GetAdapterIndex(First);
                SetDns(index, ip.First().ToString());

                return true;
            }

            return false;
        }

        private static bool ParseArgs(string[] filteredArgs, ref int adapterIndex, ref string input1, ref string input2, out int returnCode)
        {
            returnCode = 0;
            
            if (filteredArgs.Length >= 1)
            {
                if (!int.TryParse(filteredArgs[0], out adapterIndex))
                {
                    returnCode = -1;
                    return false;
                }
            }

            if (filteredArgs.Length >= 2)
            {
                if (filteredArgs[1] == "auto")
                {
                    input1 = null;
                    input2 = null;
                }
                else if (ValidateIPv4(filteredArgs[1]) || filteredArgs[1] == "auto")
                {
                    input1 = filteredArgs[1];
                }
            }

            if (filteredArgs.Length >= 3)
            {
                if (ValidateIPv4(filteredArgs[2]))
                {
                    input2 = filteredArgs[2];
                }
            }

            return true;
        }

        private static bool CheckAdmin()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    WriteLine("Please rerun as admin.");
                    return false;
                }
            }

            return true;
        }

        private static void WriteHelp()
        {
            WriteLine("");
            WriteLine("DNSS - Configure the DNS settings of an ethernet adapter. Must be run as an administrator. Pre-configured options will affect the 'first' IPv4 enabled adapter only.");
            WriteLine("");
            WriteLine("Usage: dnss");
            WriteLine("    Wizard");
            WriteLine("");
            WriteLine("Usage: dnss [OPTIONS] ADD [configurationCode:string] [adapterIndex:int] [address1:ip] [address2:ip]");
            WriteLine("    Save a configuration for later use. The provided configuration is not activated.");
            WriteLine("");
            WriteLine("Usage: dnss [OPTIONS] [configurationCode:string]");
            WriteLine("    Activate a saved configuration");
            WriteLine("");
            WriteLine("Usage: dnss LIST, dnss ls");
            WriteLine("    List all saved configurations.");
            WriteLine("");
            WriteLine("Usage: dnss REMOVE [configurationCode:string]");
            WriteLine("    Deletes a saved configuration.");
            WriteLine("");
            WriteLine("Usage: dnss [OPTIONS] [adapterIndex:int] [address1:ip] [address2:ip]");
            WriteLine("    Activate an ad hoc configuration.");
            WriteLine("");
            WriteLine("Usage: dnss NICS");
            WriteLine("    List network interfaces (with indexes).");
            WriteLine("");
            WriteLine("Usage: dnss STATUS");
            WriteLine("    Show current DNS settings.");
            WriteLine("");
            WriteLine("Usage: dnss DNS [hostName:string]");
            WriteLine("    Find `hostName` via your current dns and assign it's IP as your primary dns. This is not very reliable, hopefully you can see why.");
            WriteLine("");
            WriteLine("Options:");
            WriteLine("    -h --help          Help  - Show this.");
            WriteLine("    -q --quiet         Quiet - Suppress output.");
            WriteLine("    -f --force         Force - Overwrite when saving a configuration.");
        }

        private static int GetAdapterIndex(string description)
        {
            var mObjCol = GetNetworkAdapterConfig();
            var i = 0;
            foreach (var o in mObjCol)
            {
                var mObj = (ManagementObject)o;
                if (First.Equals(description, StringComparison.InvariantCultureIgnoreCase) && (bool)mObj["IPEnabled"])
                {
                    return i;
                }

                if ((string)mObj["Description"] == description)
                    return i;

                i++;
            }

            return -1;
        }

        private static string GetAdapterDescription(int adapterIndex)
        {
            var mObjCol = GetNetworkAdapterConfig();
            if ((mObjCol.Count - 1) >= adapterIndex)
            {
                var moArr = new ManagementObject[mObjCol.Count];
                mObjCol.CopyTo(moArr, 0);
                var mObj = moArr[adapterIndex];
                return (string)mObj["Description"];
            }

            NetworkAdapterNotFound();
            return null;
        }

        private static string CollectIp(string prompt)
        {
            string input;
            do
            {
                Write(prompt);
                input = Console.ReadLine()?.Trim();
            } while (!string.IsNullOrEmpty(input) && !ValidateIPv4(input));

            return input;
        }

        private static int CollectAdapterIndex()
        {
            var adapters = GetAdapters();
            if (adapters.Length == 0) 
                return -1;

            for (int i = 0; i < adapters.Length; i++)
            {
                WriteLine($"{i}: {adapters[i]}");
            }
            WriteLine("-------------------------------");
            Write("Select an adapter index: ");
            var adapterIndexRaw = Console.ReadLine()?.Trim();
            int adapterIndex;
            if (First.Equals(adapterIndexRaw, StringComparison.InvariantCultureIgnoreCase))
                adapterIndex = GetAdapterIndex(adapterIndexRaw);
            else if (!int.TryParse(adapterIndexRaw, out adapterIndex))
                return -1;

            return adapterIndex;
        }
        
        private static void NetworkAdapterNotFound()
        {
            WriteLine("No adapter or IPv4 is disabled");
        }

        private static string SetDns(int adapterIndex, params string[] address)
        {
            var ipValues = address == null ? null : !address.Any() ? null : address;

            var mCol = GetNetworkAdapterConfig();
            if ((mCol.Count - 1) >= adapterIndex)
            {
                var mArr = new ManagementObject[mCol.Count];
                mCol.CopyTo(mArr, 0);
                var mObj = mArr[adapterIndex];
                if ((bool)mObj["IPEnabled"])
                {
                    var mboDNS = mObj.GetMethodParameters("SetDNSServerSearchOrder");
                    if (mboDNS != null)
                    {
                        mboDNS["DNSServerSearchOrder"] = ipValues;
                        mObj.InvokeMethod("SetDNSServerSearchOrder", mboDNS, null);
                    }

                    return "Set.";
                }
            }

            NetworkAdapterNotFound();
            return "Dns not set.";
        }
        
        private static string[] GetAdapters(bool status = false)
        {
            var retVal = new List<string>();
            var mCol = GetNetworkAdapterConfig();
            foreach (var o in mCol)
            {
                var mObj = (ManagementObject)o;
                var statusString = status ? string.Join(", ", (string[])mObj["DNSServerSearchOrder"] ?? new [] { "-" }) : string.Empty;
                retVal.Add(((string)mObj["Description"]).PadRight(50) + statusString);
            }

            return retVal.ToArray();
        }

        private static ManagementObjectCollection GetNetworkAdapterConfig()
        {
            var mClass = new ManagementClass("Win32_NetworkAdapterConfiguration");
            var mObjCol = mClass.GetInstances();
            return mObjCol;
        }

        private static bool ValidateIPv4(string ipString)
        {
            if (string.IsNullOrWhiteSpace(ipString))
            {
                return false;
            }

            var splitValues = ipString.Split('.');
            return splitValues.Length == 4 && splitValues.All(r => byte.TryParse(r, out _));
        }

        private static void Write(string message)
        {
            if(!_quiet)
                Console.Write(message);
        }
        private static void WriteLine(string message)
        {
            if(!_quiet)
                Console.WriteLine(message);
        }
        
        private static string[] ListConfig()
        {
            var config = ExeConfig().Concat(ReadCustomSettings());
            return config.Select(pair => $"{pair.Key} - {pair.Value}").ToArray();
        }
        private static string[] GetConfig(string code)
        {
            var config = ExeConfig().Concat(ReadCustomSettings());
            var match = config.FirstOrDefault(p => p.Key == code).Value;
            WriteLine($"Searched for: {code}. Found: {match}");
            return match?.Split(",");
        }
        private static void RemoveConfig(string code)
        {
            var obj = new UserConfigurations();
            if (File.Exists(UserConfigFileLocation))
            {
                var str = File.ReadAllText(UserConfigFileLocation);
                obj = System.Text.Json.JsonSerializer.Deserialize<UserConfigurations>(str) ?? new UserConfigurations();
            }

            var preExisting = obj.Config.FirstOrDefault(p => p.Key == code);
            if (preExisting.Key != null)
            {
                obj.Config.Remove(preExisting);
                var str2 = System.Text.Json.JsonSerializer.Serialize<UserConfigurations>(obj);
                File.WriteAllText(UserConfigFileLocation, str2);
            }
        }
        private static IEnumerable<KeyValuePair<string, string>> ExeConfig()
        {
            var config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None).AppSettings.Settings;
            foreach (string key in config.AllKeys)
            {
                yield return new KeyValuePair<string, string>(key, config[key].Value);
            }
        }
        private static IEnumerable<KeyValuePair<string, string>> ReadCustomSettings()
        {
            if (File.Exists(UserConfigFileLocation))
            {
                var str = File.ReadAllText(UserConfigFileLocation);
                var obj = System.Text.Json.JsonSerializer.Deserialize<UserConfigurations>(str) ?? new UserConfigurations();;
                return obj.Config;
            }

            return Array.Empty<KeyValuePair<string, string>>();
        }
        private static bool WriteCustomSetting(string code, string description, string ip1, string ip2)
        {
            var obj = new UserConfigurations();
            if (File.Exists(UserConfigFileLocation))
            {
                var str = File.ReadAllText(UserConfigFileLocation);
                obj = System.Text.Json.JsonSerializer.Deserialize<UserConfigurations>(str) ?? new UserConfigurations();
            }

            var preExisting = obj.Config.FirstOrDefault(p => p.Key == code);
            if (preExisting.Key == null)
            {
                obj.Config.Add(new KeyValuePair<string, string>(code, $"{description},{ip1},{ip2}"));
            }
            else if(_force)
            {
                obj.Config.Remove(preExisting);
                obj.Config.Add(new KeyValuePair<string, string>(code, $"{description},{ip1},{ip2}"));
            }
            else
            {
                return false;
            }

            var str2 = System.Text.Json.JsonSerializer.Serialize<UserConfigurations>(obj);
            File.WriteAllText(UserConfigFileLocation, str2);

            return true;
        }
    }

    public class UserConfigurations
    {
        public UserConfigurations()
        {
            Config = new List<KeyValuePair<string, string>>();
        }

        public List<KeyValuePair<string, string>> Config { get; set; }
    }
}
