using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using _2FA_Auth.UI.Models;
using Newtonsoft.Json.Linq;

namespace _2FA_Auth.Core
{
    public class StorageCore
    {
		public StorageCallback.OnKeyAdded OnKeyAdded { get; set; }
		public StorageCallback.OnKeyRemoved OnKeyRemoved { get; set; }

		private string storagePath = null;
		private string storageFile = null;
		private string storagePassword = null;
		private string storagePswCache = null;
		private byte[] storageSalt = null;

		public StorageCore()
        {
			storagePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"2FA_Auth");
			storageFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"2FA_Auth\2fa_storage.2fa");
			storageSalt = new byte[] { 0x50, 0x48, 0x12, 0xd2, 0x32, 0x9e, 0x47, 0x7e };
		}

		/// <summary>
		/// Controlla se esiste un archivio.
		/// </summary>
		public bool IsArchiveAvaible()
		{
			return File.Exists(storageFile);
		}

		/// <summary>
		/// Crea un nuovo archivio con la password fornita.
		/// </summary>
		public bool TryCreate(string password)
		{
			try {
				string md5 = MD5Hash(password);
				Directory.CreateDirectory(storagePath);
				File.WriteAllBytes(storageFile, Encoding.UTF8.GetBytes(md5));
				storagePassword = password;
				return true;
			} catch {
				return false;
            }
		}

		/// <summary>
		/// Verifica la corrispondenza della password fornita con quella dell'archivio.
		/// </summary>
		public bool TryLogin(string password)
		{
			try {
				if (storagePswCache == null) {
					byte[] buffer = new byte[32];
					using (FileStream fs = new FileStream(storageFile, FileMode.Open, FileAccess.Read)) {
						fs.Read(buffer, 0, buffer.Length);
						fs.Close();
					}
					storagePswCache = Encoding.UTF8.GetString(buffer);
				}

				// Confronta la password inserita con quella dell'archivio.
				if (storagePswCache == MD5Hash(password)) {
					storagePassword = password;
					return true;
				} else {
					return false;
                }
			}
			catch {
				return false;
			}
		}

		/// <summary>
		/// Cambia la password attuale dell'archivio.
		/// </summary>
		public bool ChangePassword(string password)
		{
			// Decodifica l'archivio con l'attuale password.
			byte[] bytesToBeDecrypted = File.ReadAllBytes(storageFile).Skip(32).ToArray();
			if (bytesToBeDecrypted.Length <= 0) {
				File.WriteAllBytes(storageFile, Encoding.UTF8.GetBytes(MD5Hash(password)));
				return true; 
			}
			byte[] oldPassword = Encoding.UTF8.GetBytes(storagePassword);
			oldPassword = SHA256.Create().ComputeHash(oldPassword);
			byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, oldPassword);

			// Ricodifica l'archivio con la nuova password.
			byte[] newPassword = Encoding.UTF8.GetBytes(password);
			newPassword = SHA256.Create().ComputeHash(newPassword);
			byte[] bytesEncrypted = AES_Encrypt(bytesDecrypted, newPassword);
			string md5 = MD5Hash(password);
			File.WriteAllBytes(storageFile, Utils.Combine(Encoding.UTF8.GetBytes(md5), bytesEncrypted));

			// Imposta la nuova password come principale.
			storagePassword = password;
			if (Properties.Settings.Default.IsAutoLogEnabled) {
				Properties.Settings.Default.LogPassword = password;
				Properties.Settings.Default.Save();
			}
			return true;
        }

		/// <summary>
		/// Ritorna la password dell'archivio.
		/// </summary>
		public string GetPassword()
		{
			return storagePassword;
		}

		/// <summary>
		/// Esegue una copia di tutti gli account disponibili dal file importato a quello principale.
		/// </summary>
		public bool Import(string path, string password)
        {
			// Legge la password dell'archivio.
			byte[] buffer = new byte[32];
			using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read)) {
				fs.Read(buffer, 0, buffer.Length);
				fs.Close();
			}

			// Controlla se la password inserita corrisponde con quella dell'archivio.
			if (Encoding.UTF8.GetString(buffer) != MD5Hash(password)) {
				return false;
            }

			// Aggiunge tutte le chiavi all'archivio principale.
			AccountModel[] accounts = GetAllKeys(path, password);
			foreach (AccountModel account in accounts) {
				Add(account.Label, account.Secret, account.Issuer, account.Algorithm, account.Digits, account.Period, account.Date);
            }

			return true;
        }

		/// <summary>
		/// Crea una copia del file di archiviazione principale e lo esporta.
		/// </summary>
		public bool Export(string path)
		{
			try {
                string machineName = Environment.MachineName.ToLower().Replace(" ", "-");
                File.Copy(storageFile, $"{path}\\exported-{machineName}.2fa");
                return true;
			} catch {
				return false;
            }
		}

		/// <summary>
		/// Esegue una copia di tutti gli account disponibili dal file importato a quello principale.
		/// </summary>
		public bool Add(string label, string secret, string issuer, string algorithm, string digits, string period, string date)
		{
		    AccountModel[] accounts = GetAllKeys();
			Array.Resize(ref accounts, accounts.Length + 1);
			AccountModel model = new AccountModel() {
				Label = label,
				Secret = secret,
				Issuer = issuer,
				Algorithm = algorithm,
				Digits = digits,
				Period = period,
				Date = date
			};
			accounts[accounts.Length - 1] = model;

			if (SaveKeys(accounts)) {
				OnKeyAdded?.Invoke(model);
				return true;
			} else {
				return false;
            }
		}

		/// <summary>
		/// Rimuove l'elemento indicato dalla lista di archiviazione.
		/// </summary>
		public void Remove(string url)
		{
			AccountModel[] accounts = GetAllKeys();
			List<AccountModel> list = new List<AccountModel>(accounts);
			int removedIndex = -1;

			// Rimuove l'elemento indicato dalla lista di archiviazione.
			for (int i = 0; i < list.Count; i++) {
				if (list[i].Url == url) {
					list.RemoveAt(i);
					removedIndex = i;
					break;
				}
			}

			// Salva la nuova lista di archiviazione e aggiorna l'UI.
			if (removedIndex != -1) {
				if (SaveKeys(list.ToArray())) {
					OnKeyRemoved?.Invoke(removedIndex);
				}
			}
		}

		/// <summary>
		/// Ritorna una lista di tutte le chiavi disponibili nell'archivio.
		/// </summary>
		public AccountModel[] GetAllKeys(string file = null, string password = null)
		{
			if (file == null) file = storageFile;
			byte[] bytesToBeDecrypted = File.ReadAllBytes(file).Skip(32).ToArray();
            if (bytesToBeDecrypted.Length <= 0) return new AccountModel[] { };
			if (password == null) password = storagePassword;
			byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
            byte[] bytesDecrypted = AES_Decrypt(bytesToBeDecrypted, passwordBytes);

            JArray list = JArray.Parse(Encoding.UTF8.GetString(bytesDecrypted, 0, bytesDecrypted.Length));
			AccountModel[] accounts = new AccountModel[list.Count];
			for (int i = 0; i < accounts.Length; i++)
            {
				JObject item = (JObject)list[i];
				accounts[i] = new AccountModel()
				{
					Label = (string)item["label"],
					Secret = (string)item["secret"],
					Issuer = (string)item["issuer"],
					Algorithm = (string)item["algorithm"],
					Digits = (string)item["digits"],
					Period = (string)item["period"],
					Date = (string)item["date"]
				};
			}
			return accounts;
		}

		/// <summary>
		/// Salva la lista di tutte le chiavi fornite nell'archivio.
		/// </summary>
		private bool SaveKeys(AccountModel[] accounts)
		{
			JArray list = new JArray();
			for (int i = 0; i < accounts.Length; i++)
			{
				JObject item = new JObject();
				item.Add("label", accounts[i].Label);
				item.Add("secret", accounts[i].Secret);
				item.Add("issuer", accounts[i].Issuer);
				item.Add("algorithm", accounts[i].Algorithm);
				item.Add("digits", accounts[i].Digits);
				item.Add("period",  accounts[i].Period);
				item.Add("date", accounts[i].Date);
				list.Add(item);
			}

			byte[] bytesToBeEncrypted = Encoding.UTF8.GetBytes(list.ToString());
			byte[] passwordBytes = Encoding.UTF8.GetBytes(storagePassword);
			passwordBytes = SHA256.Create().ComputeHash(passwordBytes);
			byte[] bytesEncrypted = AES_Encrypt(bytesToBeEncrypted, passwordBytes);

			try {
				string md5 = MD5Hash(storagePassword);
				File.WriteAllBytes(storageFile, Utils.Combine(Encoding.UTF8.GetBytes(md5), bytesEncrypted));
				return true;
			} catch (Exception ex) {
				Console.WriteLine(ex.ToString());
				return false;
			}
		}

		/// <summary>
		/// Codifica il contenuto del file di archiviazione utilizzando l'algoritmo AES.
		/// </summary>
		public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
		{
			byte[] encryptedBytes = null;

			using (MemoryStream ms = new MemoryStream())
			{
				using (RijndaelManaged AES = new RijndaelManaged())
				{
					AES.KeySize = 256;
					AES.BlockSize = 128;

					var key = new Rfc2898DeriveBytes(passwordBytes, storageSalt, 1000);
					AES.Key = key.GetBytes(AES.KeySize / 8);
					AES.IV = key.GetBytes(AES.BlockSize / 8);

					AES.Mode = CipherMode.CBC;

					using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
					{
						cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
						cs.Close();
					}
					encryptedBytes = ms.ToArray();
				}
			}

			return encryptedBytes;
		}

		/// <summary>
		/// Decodifica il contenuto del file di archiviazione utilizzando l'algoritmo AES.
		/// </summary>
		public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
		{
			byte[] decryptedBytes = null;

			using (MemoryStream ms = new MemoryStream())
			{
				using (RijndaelManaged AES = new RijndaelManaged())
				{
					AES.KeySize = 256;
					AES.BlockSize = 128;

					var key = new Rfc2898DeriveBytes(passwordBytes, storageSalt, 1000);
					AES.Key = key.GetBytes(AES.KeySize / 8);
					AES.IV = key.GetBytes(AES.BlockSize / 8);

					AES.Mode = CipherMode.CBC;

					using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
					{
						cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
						cs.Close();
					}
					decryptedBytes = ms.ToArray();
				}
			}

			return decryptedBytes;
		}

		/// <summary>
		/// Codifica la password utilizzando l'algoritmo MD5.
		/// </summary>
		public string MD5Hash(string data)
		{
			MD5 md5 = new MD5CryptoServiceProvider();

			//compute hash from the bytes of text  
			md5.ComputeHash(ASCIIEncoding.ASCII.GetBytes(data));

			//get hash result after compute it  
			byte[] result = md5.Hash;

			StringBuilder strBuilder = new StringBuilder();
			for (int i = 0; i < result.Length; i++)
			{
				//change it into 2 hexadecimal digits  
				//for each byte  
				strBuilder.Append(result[i].ToString("x2"));
			}

			return strBuilder.ToString();
		}
    }

	public class StorageCallback
    {
		public delegate void OnKeyAdded(AccountModel account);
		public delegate void OnKeyRemoved(int index);
	}
}
