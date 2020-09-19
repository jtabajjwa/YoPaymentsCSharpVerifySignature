using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace YoPaymentsVerifySign
{
    class YoSignatureVerifier
    {
        private String dateTime;
        private String networkRef;
        private String externalRef;
        private String msisdn;
        private String narrative;
        private String amount;
        private String signature;

        private String publicKeyFile;

        private String errorMessage = "";

        public YoSignatureVerifier(String publicKeyFile_)
        {
            this.publicKeyFile = publicKeyFile_;
        }

        /*
        * Sets the base64 signature field        
        * @Param String dateTime: This is the datetime
        *        
        */
        public void SetDateTime(String dateTime_)
        {
            this.dateTime = dateTime_;
        }
        /*
        *       
        * @Param String signature: This is the network reference.
        *        
        */
        public void SetNetworkRef(String networkRef_)
        {
            this.networkRef = networkRef_;
        }
        /*
        * Sets the base64 signature field        
        * @Param String signature: This is the external ref
        *        
        */
        public void SetExternalRef(String externalRef_)
        {
            this.externalRef = externalRef_;
        }
        /*
        *    
        * @Param String signature: This is the msisdn field of the transaction
        *        
        */
        public void SetMsisdn(String msisdn_)
        {
            this.msisdn = msisdn_;
        }
        /*
        *       
        * @Param String narrative: This is the narrative of the transaction.
        *        
        */
        public void SetNarrative(String narrative_)
        {
            this.narrative = narrative_;
        }
        /*
        * Sets the amount field      
        * @Param String amount: This is the amount of the transaction.
        *        
        */
        public void SetAmount(String amount_)
        {
            this.amount = amount_;
        }

        /*
        * Sets the base64 signature field        
        * @Param String signature: This is the base64 encoded signature.
        *        
        */
        public void SetSignature(String signature_)
        {
            this.signature = signature_;
        }


        /*
        * Returns: True if the signature verification passed or False if it failed
        * or an error occurred.       
        */
        public bool verify()
        {
            if (dateTime == null)
            {
                this.errorMessage = "dateTime Field is null";
                return false;
            }
            if (amount == null)
            {
                this.errorMessage = "amount Field is null";
                return false;
            }
            if (narrative == null)
            {
                this.errorMessage = "narrative Field is null";
                return false;
            }
            if (networkRef == null)
            {
                this.errorMessage = "networkRef Field is null";
                return false;
            }
            if (externalRef == null)
            {
                this.errorMessage = "externalRef Field is null";
                return false;
            }
            if (msisdn == null)
            {
                this.errorMessage = "msisdn Field is null";
                return false;
            }

            String signedData = dateTime + amount + narrative + networkRef + externalRef + msisdn;
            bool v = VerifyTheSignature(signature, signedData);
            if (v)
            {
                return true;
            }
            else
            {
                this.errorMessage = "Signature verification failed.";
                return false;
            }
        }

        public String GetError()
        {
            return this.errorMessage;
        }

        /*
        * @Param signature: This is the base64 string of data data to be verified.
        * @Param data: This is the string data that was signed       
        *        
        * Returns Bool: True if signature passed or false if failed | an error.       
        */

        private bool VerifyTheSignature(String base64Signature, String signedData)
        {
            try
            {
                byte[] signature_ = Convert.FromBase64String(base64Signature);

                byte[] data = Encoding.UTF8.GetBytes(signedData);

                if (!File.Exists(publicKeyFile))
                {
                    this.errorMessage = "Verification failed: PublicKey Certificate: "
                        + publicKeyFile + " does not exists";
                    return false;
                }

                var x509 = new X509Certificate2(publicKeyFile);

                if (!(x509.PublicKey.Key is RSACryptoServiceProvider rsa))
                {
                    this.errorMessage = "Verification failed: Failed to load x509.PublicKey";
                    return false;
                }

                string sha1O_id = CryptoConfig.MapNameToOID("SHA1");

                //use the certificate to verify data against the signature
                bool sha1_valid = rsa.VerifyData(data, sha1O_id, signature_);

                return sha1_valid;
            }
            catch (Exception e)
            {
                this.errorMessage = "Verification failed: " + e.Message;
                return false;
            }
        }
    }
}
