// Forms example of reading assembly's manifest https://support.microsoft.com/en-us/help/319292/how-to-embed-and-access-resources-by-using-visual-c
using System;
// define definition of a stream
using System.IO;
// define assembly class to reach methods for access to resources
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
//using System.Security.Cryptography.X509Certificates.X509ChainPolicy;

namespace Certs
{
    class MainClass
	{
		 
		static Stream _by;
		static BinaryReader _byteReader;
		static StreamReader _textStreamReader;
        public static void Main(string[] args)
        {
            // check that name on cert = name of host user is connecting to
            // var x5092 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificateBytes);
            // string hostName = x5092.GetNameInfo(System.Security.Cryptography.X509Certificates.X509NameType.DnsName, false);
            // bool hostNameMatch = string.Compare(hostName, this.Server, true) == 0;

            // need to build x509chain obj , call build with cert, examine chainstatus property to see why failed.
			// open store
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);
            
			byte[] b = GetStreamBytes();
			var x509 = new Mono.Security.X509.X509Certificate(b);
            var chain = new Mono.Security.X509.X509Chain();
            bool certificateStatus = chain.Build(x509);
			Console.WriteLine(certificateStatus);
            // output true


   //         X509Certificate2 newcert = new X509Certificate2();
			//byte[] b = GetStreamBytes();
			//newcert.Import(b);
			//buildChain(newcert);
			//byte[] b = GetStreamBytes();
			//newcert.Import(b);
			//store.Add(newcert);

			//PrintStore();
			//PrintMore();
            
            // 3

           // read certs



         
            
		}
		static void TestX509Chain(){
			//Create new X509 store from local certificate store.
            X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

            //Output store information.
            Console.WriteLine("Store Information");
            Console.WriteLine("Number of certificates in the store: {0}", store.Certificates.Count);
            Console.WriteLine("Store location: {0}", store.Location);
            Console.WriteLine("Store name: {0} {1}", store.Name, Environment.NewLine);

            //Put certificates from the store into a collection so user can select one.
            X509Certificate2Collection fcollection = (X509Certificate2Collection)store.Certificates;
            X509Certificate2Collection collection = X509Certificate2UI.SelectFromCollection(fcollection, "Select an X509 Certificate", "Choose a certificate to examine.", X509SelectionFlag.SingleSelection);
            X509Certificate2 certificate = collection[0];
            X509Certificate2UI.DisplayCertificate(certificate);
            //Output chain information of the selected certificate.
            X509Chain ch = new X509Chain();
            ch.Build(certificate);
            Console.WriteLine("Chain Information");
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);
            //Output chain element information.
            Console.WriteLine("Chain Element Information");
            Console.WriteLine("Number of chain elements: {0}", ch.ChainElements.Count);
            Console.WriteLine("Chain elements synchronized? {0} {1}", ch.ChainElements.IsSynchronized, Environment.NewLine);

            foreach (X509ChainElement element in ch.ChainElements)
            {
                Console.WriteLine("Element issuer name: {0}", element.Certificate.Issuer);
                Console.WriteLine("Element certificate valid until: {0}", element.Certificate.NotAfter);
                Console.WriteLine("Element certificate is valid: {0}", element.Certificate.Verify());
                Console.WriteLine("Element error status length: {0}", element.ChainElementStatus.Length);
                Console.WriteLine("Element information: {0}", element.Information);
                Console.WriteLine("Number of element extensions: {0}{1}", element.Certificate.Extensions.Count, Environment.NewLine);

                if (ch.ChainStatus.Length > 1)
                {
                    for (int index = 0; index < element.ChainElementStatus.Length; index++)
                    {
                        Console.WriteLine(element.ChainElementStatus[index].Status);
                        Console.WriteLine(element.ChainElementStatus[index].StatusInformation);
                    }
                }
            }
            store.Close();
        }

		static void buildChain(X509Certificate2 cert){
			// Output chain information of the selected certificate.
			var certificate = cert;
            X509Chain ch = new X509Chain();
            ch.Build(certificate);
            Console.WriteLine("Chain Information");
            ch.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            Console.WriteLine("Chain revocation flag: {0}", ch.ChainPolicy.RevocationFlag);
            Console.WriteLine("Chain revocation mode: {0}", ch.ChainPolicy.RevocationMode);
            Console.WriteLine("Chain verification flag: {0}", ch.ChainPolicy.VerificationFlags);
            Console.WriteLine("Chain verification time: {0}", ch.ChainPolicy.VerificationTime);
            Console.WriteLine("Chain status length: {0}", ch.ChainStatus.Length);
            Console.WriteLine("Chain application policy count: {0}", ch.ChainPolicy.ApplicationPolicy.Count);
            Console.WriteLine("Chain certificate policy count: {0} {1}", ch.ChainPolicy.CertificatePolicy.Count, Environment.NewLine);
		}
        static void PrintMore()
		{
			X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            try
            {

                X509Certificate2Collection certificatesInStore = store.Certificates;
                foreach (X509Certificate2 cert3 in certificatesInStore)
                {
                    Console.WriteLine(cert3.GetExpirationDateString());
                    Console.WriteLine(cert3.Issuer);
                    Console.WriteLine(cert3.GetEffectiveDateString());
                    Console.WriteLine(cert3.GetNameInfo(X509NameType.SimpleName, true));
                    Console.WriteLine(cert3.HasPrivateKey);
                    //results += cert3.GetCertHashString();
                    Console.WriteLine(cert3.SubjectName.Name);
                    Console.WriteLine(cert3.GetCertHashString());
                    Console.WriteLine("-----------------------------------");

                }
            }
            finally
            {
                store.Close();
            }
		}
		static void PrintStore()
		{
			Console.WriteLine("\r\nExists Certs Name and Location");
			Console.WriteLine("------ ----- -------------------------");

			foreach (StoreLocation storeLocation in (StoreLocation[])
				Enum.GetValues(typeof(StoreLocation)))
			{
				foreach (StoreName storeName in (StoreName[])
					Enum.GetValues(typeof(StoreName)))
				{
					X509Store store = new X509Store(storeName, storeLocation);

					try
					{
						store.Open(OpenFlags.OpenExistingOnly);

						Console.WriteLine("Yes    {0,4}  {1}, {2}",
							store.Certificates.Count, store.Name, store.Location);
					}
					catch (CryptographicException)
					{
						Console.WriteLine("No           {0}, {1}",
							store.Name, store.Location);
					}
				}
			}
		}
        static byte[] GetStreamBytes()
		{
			string bs = "MIIDLDCCAhQCCQCNI5x+69QDPDANBgkqhkiG9w0BAQsFADB/MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDzANBgNVBAoMBlNwbHVuazEXMBUGA1UEAwwOU3BsdW5rQ29tbW9uQ0ExITAfBgkqhkiG9w0BCQEWEnN1cHBvcnRAc3BsdW5rLmNvbTAeFw0xODA1MjAwMzQzMzZaFw0yMTA1MTkwMzQzMzZaMDExGjAYBgNVBAMMEXNwbHVuay1WaXJ0dWFsQm94MRMwEQYDVQQKDApTcGx1bmtVc2VyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArZ0/vIzM3Bf9+iaQNICYYBms8BkbfGwRNqnXj1TemNdkkmonZIxQUYzsiwvWc4VcegW+NvfnXFDvAHAXdTHFZpr/2rO1E+l59BLeaipnB0BrqfwnIUOvXpuY5PCwSDujXNDxfkQl0GHiPwGJfQnXFnRvHAu1eEfgZT8VAKwinAo3I5sqc0M5ze1xdWuH9I1A2J6Pg4MQ/zwG/nTUWsQfD3ZrNXFkskN0eAC6Not0OEx74L58fOTwIgZL0fJEzOJ33ZTPwpKC5G07A7fHv8ECVa4dg3NOGRHHc52OnOSQyX9seI0VtbhXPRMdOG7s/OBc6yb4NOsB5MZL2ADEwQ2jUQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCJucPRlheNkOr3JiFyxD8UQ/jsGx58ccQ2EdO9+gTI4xXxm5ZQ9Pd+KSb9Hk+CuWS912lhNj6wynComN6Rlr7Ijc+3PSEeOxSbyUELKVyywaSO4D1OlA9PGdtX2lJI3inA+G9epIWjcqTGuuZEhmyc62WuGEs3I0U2kKbPAyS34ZtBYipK44FjsyHnQj5TCFY5CcnGWq3aXRk8H+tX75wRV0hrv4GPMDmukTTUv3lxSS5U/RbwTGzPQW/PCiIPpBuJA00vy4WXcuJh9CykQqGmV7aBcrRkJAAqR3npl6BL1iVk7g+5/hGxpceHFhrFzOov1t4gBWIhkvMUmd5aC1tw";
			Assembly _assembly;

            // read resource from current executing assembly, get instance of that assembly
             _assembly = Assembly.GetExecutingAssembly();
            // read resource to a stream

			//var b64string = _assembly.GetManifestResourceStream("Certs.splunk.crt").ToString();
             
			byte[] bytes = Convert.FromBase64String(bs);
			return bytes;
		}

		static byte[] ReadAllBytes(Stream stream)
        {
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                return ms.ToArray();
            }
        }

		static Stream GetStream()
        {
			try
			{
				Assembly _assembly;

				// read resource from current executing assembly, get instance of that assembly
				_assembly = Assembly.GetExecutingAssembly();
				// read resource to a stream

				_by = _assembly.GetManifestResourceStream("Certs.splunk.crt");
			}
            catch
            {
                Console.WriteLine("Error accessing resources!");
            }
            return _by;
        }
		 static BinaryReader GetBinaryReader()
			{
			try
			{
				Assembly _assembly;

				// read resource from current executing assembly, get instance of that assembly
				_assembly = Assembly.GetExecutingAssembly();
				// read resource to a stream

				_byteReader = new BinaryReader(_assembly.GetManifestResourceStream("Certs.splunk.crt"));
			}
                catch
            {
                Console.WriteLine("Error accessing resources!");
            }
			return _byteReader;
			}
		static StreamReader GetStreamReader()
        {
            try
            {
                Assembly _assembly;
				 
                // read resource from current executing assembly, get instance of that assembly
                _assembly = Assembly.GetExecutingAssembly();
                // read resource to a stream
                _textStreamReader = new StreamReader(_assembly.GetManifestResourceStream("Certs.splunk.txt"));
            }
            catch
            {
                Console.WriteLine("Error accessing resources!");
            }
            return _textStreamReader;
        }
    }
}
//static bool VerifyCertificate(byte[] primaryCertificate, IEnumerable<byte[]> additionalCertificates)
//{
//    var chain = new X509Chain();
//    foreach (var cert in additionalCertificates.Select(x => new X509Certificate2(x)))
//    {
//        chain.ChainPolicy.ExtraStore.Add(cert);
//    }

//    // You can alter how the chain is built/validated.
//    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
//    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage;

//    // Do the preliminary validation.
//    var primaryCert = new X509Certificate2(primaryCertificate);
//    if (!chain.Build(primaryCert))
//        return false;

//    // Make sure we have the same number of elements.
//    if (chain.ChainElements.Count != chain.ChainPolicy.ExtraStore.Count + 1)
//        return false;

//    // Make sure all the thumbprints of the CAs match up.
//    // The first one should be 'primaryCert', leading up to the root CA.
//    for (var i = 1; i < chain.ChainElements.Count; i++)
//    {
//        if (chain.ChainElements[i].Certificate.Thumbprint != chain.ChainPolicy.ExtraStore[i - 1].Thumbprint)
//            return false;
//    }

//    return true;
//}