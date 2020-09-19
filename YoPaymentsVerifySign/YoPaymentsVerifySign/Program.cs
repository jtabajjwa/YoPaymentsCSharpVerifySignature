using System;

namespace YoPaymentsVerifySign
{
    class MainClass
    {
        //Set this to the right path of the ceritificate file.
        private static string publicKeyFile = "Yo_Uganda_Public_Certificate.crt";

        public static void Main(string[] args)
        {

            /*In your code, obtain the following data from the POST fields of the request*/
            String date_time = "2019-06-21 10:09:21";
            String network_ref = "1462967855";
            String external_ref = "3-Joseph-Tabajjwa";
            String msisdn = "256783086794";
            String narrative = "Testing";
            String amount = "2000";
            String signature = "RTyGxIwp83Lb9Lo03yGOSyXKDjY3vmgvPjoOzFb79CWvUttvnnFh4Ln1/Ur71YucjXpkfTdhdz2GyLAWVtCxl3iqox3haZMIX/9JVcYh4tt5zipwUo0CLgRVehsyJlUs70ph7TJ1KU/qMcOz60HWLsJDPv95n4Dqdh3bTHg/f+XovxD5Qde7sGEeXWnAQBlq5Bb2dFtw9k6vyI+4BE5h++CKgCr/7wzvKM3hij4mTqIRW0Z+DtZK7cIgtmckr0w7F9eW+YCiymTRP4sdRqinEvDADW49/dDLq1gTnO83RxpSTmHw5NavvRGjszC3Fgub5t2gT52Kr9oNHZhgiBZIDg==";

            YoSignatureVerifier yoVerifierObj = new YoSignatureVerifier(publicKeyFile);
            yoVerifierObj.SetDateTime(date_time);
            yoVerifierObj.SetNetworkRef(network_ref);
            yoVerifierObj.SetExternalRef(external_ref);
            yoVerifierObj.SetMsisdn(msisdn);
            yoVerifierObj.SetNarrative(narrative);
            yoVerifierObj.SetAmount(amount);
            yoVerifierObj.SetSignature(signature);

            if (yoVerifierObj.verify())
            {
                Console.WriteLine("Signature verification passed!");
            }
            else
            {
                Console.WriteLine("Error");
                Console.WriteLine(yoVerifierObj.GetError());
            }
        }

    }

}
