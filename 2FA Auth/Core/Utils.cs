using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Media.Imaging;

namespace _2FA_Auth.Core
{
    public class Utils
    {
        /// <summary>
        /// Decodifica l'indirizzo URL fornito e ne recupera tutti i parametri che costituiscono
        /// un indirizzo di tipo TOTP, impostando anche valori di default in caso non siano presenti.
        /// </summary>
		public static string[] DecodeTotpUrl(string url)
        {
            // Controlla che l'indirizzo non sia vuoto.
            if (String.IsNullOrEmpty(url)) {
                return null;
            }

            // Controlla che l'indirizzo sia di tipo TOTP.
            if (!url.StartsWith("otpauth://totp/")) {
                return null;
            }

            string[] result = new string[6];
            string[] urlSegments = url.Split('?');

            // Ricava il 'nome utente'.
            string keyLabel = urlSegments[0].Replace("otpauth://totp/", "");
            if (keyLabel.Contains(":")) {
                string[] parts = keyLabel.Split(':');
                keyLabel = parts[1];
            }
            result[0] = keyLabel;

            // Ricava tutti gli altri parametri.
            string[] querySegments = url.Replace(urlSegments[0] + "?", "").Split('&');
            foreach (string segment in querySegments)
            {
                string[] parts = segment.Split('=');
                if (parts.Length > 0)
                {
                    string key = parts[0].Trim(new char[] { '?', ' ' });
                    string val = parts[1].Trim();

                    if (key.ToLower().Contains("secret")) {
                        result[1] = val;
                    } else if (key.ToLower().Contains("issuer")) { 
                        result[2] = val;
                    } else if (key.ToLower().Contains("algorithm")) {
                        result[3] = val;
                    } else if (key.ToLower().Contains("digits")) {
                        result[4] = val;
                    } else if (key.ToLower().Contains("period")) {
                        result[5] = val;
                    }
                }
            }

            // Controlla tutti i parametri per impostatre eventauli valori di default.
            if (String.IsNullOrEmpty(result[0])) {
                result[0] = "Unknown";
            } 
            if (String.IsNullOrEmpty(result[1])) {
                return null;
            } 
            if (String.IsNullOrEmpty(result[2])) {
                result[2] = "Unknown";
            } 
            if (String.IsNullOrEmpty(result[3])) {
                result[3] = "SHA1";
            } 
            if (String.IsNullOrEmpty(result[4])) {
                result[4] = "6";
            } 
            if (String.IsNullOrEmpty(result[5])) {
                result[5] = "30";
            }

            return result;
        }

        /// <summary>
        /// Effettua una richiesta di tipo POST all'indirizzo URL fornito con allegato un immagine
        /// contentente il codice QR che il sito 'qrserver.com' dovrà analizzare.
        /// </summary>
        public static async Task<Stream> SendPostImage(string url, string fileName, byte[] fileBytes)
        {
            HttpContent fileSizeContent = new StringContent(fileBytes.Length.ToString());
            HttpContent fileBytesContent = new ByteArrayContent(fileBytes);

            using (var client = new HttpClient())
            using (var formData = new MultipartFormDataContent())
            {
                formData.Add(fileSizeContent, "MAX_FILE_SIZE", "MAX_FILE_SIZE");
                formData.Add(fileBytesContent, "file", fileName);
                var response = await client.PostAsync(url, formData);
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }
                return await response.Content.ReadAsStreamAsync();
            }
        }

        /// <summary>
        /// Converte un'immagine di tipo 'Bitmap' in 'BitmapImage'.
        /// </summary>
        public static BitmapImage ToBitmapImage(Bitmap bitmap)
        {
            using (var memory = new MemoryStream())
            {
                bitmap.Save(memory, ImageFormat.Png);
                memory.Position = 0;

                var bitmapImage = new BitmapImage();
                bitmapImage.BeginInit();
                bitmapImage.StreamSource = memory;
                bitmapImage.CacheOption = BitmapCacheOption.OnLoad;
                bitmapImage.EndInit();
                bitmapImage.Freeze();

                return bitmapImage;
            }
        }

        /// <summary>
        /// Esegue la copia di un array,
        /// </summary>
        public static byte[] CopyOf(byte[] src, int len)
        {
            byte[] dest = new byte[len];
            Array.Copy(src, 0, dest, 0, len);
            return dest;
        }

        /// <summary>
        /// Combina assieme due array.
        /// </summary>
        public static byte[] Combine(byte[] first, byte[] second)
        {
            byte[] ret = new byte[first.Length + second.Length];
            Buffer.BlockCopy(first, 0, ret, 0, first.Length);
            Buffer.BlockCopy(second, 0, ret, first.Length, second.Length);
            return ret;
        }

        /// <summary>
        /// Ritorna l'architettura del sistema operativo sul quale è in esecuzione il programma.
        /// </summary>
        public static string GetSystemArchitecture()
        {
            return (Marshal.SizeOf(IntPtr.Zero) == 8 ? " (x64)" : " (x86)");
        }
    }
}
