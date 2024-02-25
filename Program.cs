using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Threading.Tasks;
using VirusTotalNet.Objects;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using System.Net.Http.Headers;


namespace VirusTotalNet.Examples;

internal class Program
{
    /*
     //Simple PROGRAM THAT SCAN URLs; will show different Databases results of the scanned url 
      if alert exit then DETECTED = TRUE
      
      if not alert on the url then DETECTED = FALSE (Meaning that url is clean of malicious)


    REMEMBER this is not an ANTIVIRUS program it just collect information from different database engines results

     */

    //PROGRAM URL SCAN
    private static async Task Main(string[] args)
    {
        // int countMalicious = 0;
        //VirusTotal API KEY 
        //NOTE: Use The API key provided from you account of VirusTotal
        //NOTA: Ingresa la API proveida por VIRUS TOTAL desde tu cuenta

        //MI APIKEY PROVEIDA DESDE VIRUSTOTAL USALA SIN PROBLEMAS(Puede tener limitaciones)
        using VirusTotal virusTotal = new VirusTotal("e58baf343a9b9424ae745ff00ad22874e895c02fe5c6ceec92a8aac93684649e");

        //INPUT AN SPECIFIC URL THAT YOU WANT TO SCAN (INGRESE UN URL A ESCANEAR)
        Console.WriteLine("Enter URL to scan");
        string scanUrl = Console.ReadLine();

        UrlReport urlReport = new UrlReport();
        try
        {
            urlReport = await virusTotal.GetUrlReportAsync(scanUrl);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }



        bool urlHasBeenScannedBefore = urlReport.ResponseCode == UrlReportResponseCode.Present;
        Console.WriteLine("URL has been scanned before: " + (urlHasBeenScannedBefore ? "Yes" : "No"));

        //if the URL has been already scanned, the results are embedded inside the report.
        //Si la URL ya ha sido escaneada, los resultados se incrustan en el informe.
        if (urlHasBeenScannedBefore)
        {
            PrintScan(urlReport);
        }
        else
        {
            UrlScanResult urlResult = await virusTotal.ScanUrlAsync(scanUrl);
            PrintScan(urlResult);
        }

        Console.WriteLine("ENTER AN IP ADDRESS");
        string ipAddr = Console.ReadLine();

        var client = new HttpClient();

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Get,
            RequestUri = new Uri("https://www.virustotal.com/api/v3/ip_addresses/" + ipAddr),
            Headers =
            {
                   { "accept", "application/json" },
                   { "x-apikey", "e58baf343a9b9424ae745ff00ad22874e895c02fe5c6ceec92a8aac93684649e" },
            },
        };

        using (var response = await client.SendAsync(request))
        {
            response.EnsureSuccessStatusCode();
            var body = await response.Content.ReadAsStringAsync();
            Console.WriteLine(body);
        }





        Console.WriteLine("Si Detected = false entonces no se enconntraron amanezas" + Environment.NewLine + "Si Detected = true entonces si se encontro sospecha de url malicioso");

        Console.WriteLine();
        Console.WriteLine("PRESS EMTER TO EXIT THE PROGRAM");
        Console.ReadLine();



    }
    private static void PrintScan(UrlScanResult scanResult)
    {
        Console.WriteLine("Scan ID: " + scanResult.ScanId);
        Console.WriteLine("Message: " + scanResult.VerboseMsg);

        Console.WriteLine();

    }

    private static void PrintScan(ScanResult scanResult)
    {
        Console.WriteLine("Scan ID: " + scanResult.ScanId);
        Console.WriteLine("Message: " + scanResult.VerboseMsg);

        Console.WriteLine();

    }


    //FUNCTION TO PRINT THE FILE RESULTS
    private static void PrintScan(FileReport fileReport)
    {
        Console.WriteLine("Scan ID: " + fileReport.ScanId);
        Console.WriteLine("Message: " + fileReport.VerboseMsg);

        if (fileReport.ResponseCode == FileReportResponseCode.Present)
        {
            foreach (KeyValuePair<string, ScanEngine> scan in fileReport.Scans)
            {

                Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
            }
        }

        Console.WriteLine();

    }

    //Function to Print URl results
    private static void PrintScan(UrlReport urlReport)
    {
        Console.WriteLine("Scan Id: " + urlReport.ScanId);
        Console.WriteLine("Message Id: " + urlReport.VerboseMsg);

        if (urlReport.ResponseCode == UrlReportResponseCode.Present)
        {
            foreach (KeyValuePair<string, UrlScanEngine> scan in urlReport.Scans)
            {
                //He Agregado una colores a los resultados para una mejor visualización para una mejor
                //visualización de los posibles motores de busqueda que hayan detectado actividad maliciosa

                //Los Motores de Antivirus que detectaron el sitio
                //como malicioso se mostrara en 
                if (scan.Value.Detected == true)
                {
                    Console.BackgroundColor = ConsoleColor.Red;
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
                }
                else
                {

                    //The Antivirus Engine that detected site as secure will be shown in Green
                    //Los Motores de Antivirus que hayan detectado la url como segure se mostrara en verde
                    Console.BackgroundColor = ConsoleColor.Green;
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Key, scan.Value.Detected);
                }

                Console.ResetColor();

            }
        }
        Console.WriteLine();

    }


    /*
     ESTE PROGRAMA NO ES UN ANTIVIRUS

    -Este programa recopila informacion de
    Base de Datos de Algunos Motores de Antivurus,
    y muestra su resultado. De esa manera se podra tener
    mas información sobre la seguridad del sitio.

     */

    //API version gratuita de VIRUS TOTAL 4 request max
    //Código Original
    //https://github.com/Genbox/VirusTotalNet



}