using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Threading;
using System.Collections.ObjectModel;
using _2FA_Auth.UI.Helpers;
using _2FA_Auth.UI.Models;
using _2FA_Auth.Core;
using Newtonsoft.Json.Linq;

namespace _2FA_Auth.UI.Pages
{
	enum Tabs
    {
		None = 0,
		AllKeys = 1,
		AddKey = 2,
		Import = 3,
		Export = 4,
		Security = 5,
		Settings = 6
    }

    public partial class MainWindow : Window
    {
		private Tabs currentTab;
		private ObservableCollection<AccountModel> accounts;
		private DispatcherTimer dispatcherTimer;
		private StorageCore storage;
		private string importPath;

		public MainWindow()
		{
			InitializeComponent();

			storage = new StorageCore();
			storage.OnKeyAdded += Storage_OnKeyAdded;
			storage.OnKeyRemoved += Storage_OnKeyRemoved;
			accounts = new ObservableCollection<AccountModel>();
			dispatcherTimer = new DispatcherTimer();
			dispatcherTimer.Tick += new EventHandler(dispatcherTimer_Tick);
			dispatcherTimer.Interval = new TimeSpan(0, 0, 1);
			DataContext = this;
			Title += Utils.GetSystemArchitecture();
		}

		private void Storage_OnKeyAdded(AccountModel account)
        {
			// Aggiorna l'interfaccia UI.
			Tx_KeysCount.Text = (accounts.Count + 1).ToString();

			// Aggiunge l'elemento alla lista.
			account.Id = accounts.Count;
			accounts.Add(account);
		}

		private void Storage_OnKeyRemoved(int index)
		{
			// Rimuove l'elemento dalla lista.
			accounts.RemoveAt(index);
			Tx_KeysCount.Text = accounts.Count.ToString();

			// Riordina gli indici di tutte le chiavi rimanenti.
			for (int i = 0; i < accounts.Count; i++) {
				accounts[i].Id = i;
			}
		}

		public ICommand ExpandCommand => new RelayCommand(param => {
			accounts[(int)param].IsActived = accounts[(int)param].IsActived == true ? false : true;
		});

		public ICommand RemoveCommand => new RelayCommand(param => {
			MessageBoxResult result = MessageBox.Show("Are you sure you want to delete this item?", "Confirm", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
			if (result == MessageBoxResult.Yes) {
				storage.Remove(accounts[(int)param].Url);
			}
		});

		public ICommand CopyCommand => new RelayCommand(param => {
			Clipboard.SetText(accounts[(int)param].Code.Replace(" ", ""));
		});

		private void Window_Loaded(object sender, RoutedEventArgs e)
        {
			// Controlla l'esistenza di un archivio.
			if (storage.IsArchiveAvaible()) {
				if (Properties.Settings.Default.IsAutoLogEnabled) {
					if (storage.TryLogin(Properties.Settings.Default.LogPassword)) {
						Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
					} else {
						Tab_Login.Visibility = Visibility.Visible;
					}
				} else {
					Tab_Login.Visibility = Visibility.Visible;
				}
			} else {
				Tab_Create.Visibility = Visibility.Visible;
			}
		}

		private bool ChangeTab(Tabs tab) {
			if (tab == currentTab) return false;

			Grid[] tabs = new Grid[] { Tab_AllKeys, Tab_AddKey, Tab_Import, Tab_Export, Tab_Security, Tab_Settings };
			Button[] btns = new Button[] { Btn_AllKeys, Btn_AddKey, Btn_Import, Btn_Export, Btn_Security, Btn_Settings };

			for (int i = 0; i < 6; i++)
            {
				if (i + 1 == (int)tab) 
				{
					btns[i].BorderThickness = new Thickness(0, 0, 0, 5);
					tabs[i].Visibility = Visibility.Visible;
				}
				else
                {
					btns[i].BorderThickness = new Thickness(0);
					tabs[i].Visibility = Visibility.Collapsed;
				}
			}

			// Arresta il timer delle chiavi di sicurezza.
			if (dispatcherTimer.IsEnabled) {
				dispatcherTimer.Stop();
			}

			// Imposta la tab richiesta come corrente.
			currentTab = tab;
			return true;
		}

		private void dispatcherTimer_Tick(object sender, EventArgs e)
		{
			for (int i = 0; i < accounts.Count; i++)
			{
				int splitDigits = int.Parse(accounts[i].Digits) / 2;
				int period = int.Parse(accounts[i].Period);
				long diff = period - ((_2FACore.CurrentTimeMillis() / 1000) % period);
                string code = _2FACore.generateCurrentNumberString(accounts[i].Secret, accounts[i].Algorithm, accounts[i].Digits, accounts[i].Period);
				accounts[i].Code = $"{code.Substring(0, splitDigits)}  {code.Substring(splitDigits, splitDigits)}";
                accounts[i].Value = 100 - ((diff * 100) / period);
            }
		}

        private void Btn_Login_Click(object sender, RoutedEventArgs e)
        {
			if (String.IsNullOrEmpty(Tb_LoginPassword.Password)) {
				MessageBox.Show("Fill in all required fields!");
				return;
			}

			// Controlla se la password inserita corrisponde a quella dell'archivio.
			if (storage.TryLogin(Tb_LoginPassword.Password)) {
				Tab_Login.Visibility = Visibility.Collapsed;
				Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
			}
			else {
				Tab_Login.Visibility = Visibility.Visible;
			}
		}

        private void Btn_Create_Click(object sender, RoutedEventArgs e)
        {
			if (String.IsNullOrEmpty(Tb_CreatePassword.Password)) {
				MessageBox.Show("Fill in all required fields!");
				return;
			}

			// Crea un nuovo archivo con la password inserita.
			if (storage.TryCreate(Tb_CreatePassword.Password)) {
				Tab_Create.Visibility = Visibility.Collapsed;
				Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
			} else {
				Tab_Create.Visibility = Visibility.Visible;
			}
		}

		private void Tb_LoginPassword_KeyDown(object sender, KeyEventArgs e)
		{
			if (e.Key == Key.Enter) {
				Btn_Login.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
			}
		}

		private void Tb_CreatePassword_KeyDown(object sender, KeyEventArgs e)
        {
			if (e.Key == Key.Enter) {
				Btn_Create.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
			}
		}

		// Navigation bar buttons.

        private void Btn_AllKeys_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.AllKeys)) {
				return;
			}

			// Aggiunge tutti gli account disponibili alla lista.
			if (List_Effects.ItemsSource == null)
			{
				AccountModel[] allKeys = storage.GetAllKeys();
				Tx_KeysCount.Text = allKeys.Length.ToString();
				for (int i = 0; i < allKeys.Length; i++) {
					AccountModel key = allKeys[i];
					key.Id = i;
					accounts.Add(key);
				}
				List_Effects.ItemsSource = accounts;
			}

			// Avvia il timer delle chiavi di sicurezza.
			if (!dispatcherTimer.IsEnabled){
				dispatcherTimer.Start();
			}
		}

        private void Btn_AddKey_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.AddKey)) {
				return;
			}

			// Seleziona il primo metodo di input come principale.
			Btn_SectionQr.IsChecked = true;
			Btn_SectionQr.RaiseEvent(new RoutedEventArgs(RadioButton.ClickEvent));
		}

        private void Btn_Import_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.Import)) {
				return;
			}

			// Reimposta i valori iniziali dei campi di inserimento.
			importPath = null;
			Btn_BrowseArchive.Content = "Browse...";
			Tb_ArchivePassword.Password = "";
		}

        private void Btn_Export_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.Export)) {
				return;
			}
		}

        private void Btn_Security_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.Security)) {
				return;
			}

			// Reimposta i valori iniziali dei campi di inserimento.
			Tb_ArchivePassword.Password = "";
		}

        private void Btn_Settings_Click(object sender, RoutedEventArgs e)
        {
			if (!ChangeTab(Tabs.Settings)) {
				return;
			}

			// Reimposta i valori iniziali dei campi di inserimento.
			Sw_RequestPassword.IsChecked = !Properties.Settings.Default.IsAutoLogEnabled;
		}

        private void Btn_Logout_Click(object sender, RoutedEventArgs e)
        {
			this.Close();
		}

		// Add key buttons.

		private void Btn_SectionQr_Click(object sender, RoutedEventArgs e)
		{
			if (Btn_SectionQr.IsChecked == true) {
				Tab_QrCode.Visibility = Visibility.Visible;
				Tab_SecureKey.Visibility = Visibility.Collapsed;
				Tab_FullUrl.Visibility = Visibility.Collapsed;

				// Reimposta i valori iniziali dei campi di inserimento.
				Btn_AddQrCode.Content = "Browse file...";
				Tab_QrCodeLoading.Visibility = Visibility.Collapsed;
			}
		}

		private void Btn_SectionKey_Click(object sender, RoutedEventArgs e)
		{
			if (Btn_SectionKey.IsChecked == true) {
				Tab_QrCode.Visibility = Visibility.Collapsed;
				Tab_SecureKey.Visibility = Visibility.Visible;
				Tab_FullUrl.Visibility = Visibility.Collapsed;

				// Reimposta i valori iniziali dei campi di inserimento.
				Tb_KeyLabel.Text = "";
				Tb_KeyIssuer.Text = "";
				Tb_KeySecret.Text = "";
				Cb_KeyAlgorithm.SelectedIndex = 0;
				Cb_KeyDigits.SelectedIndex = 0;
				Tb_KeyPeriod.Text = "30";
			}
		}

		private void Btn_SectionUrl_Click(object sender, RoutedEventArgs e)
		{
			if (Btn_SectionUrl.IsChecked == true) {
				Tab_QrCode.Visibility = Visibility.Collapsed;
				Tab_SecureKey.Visibility = Visibility.Collapsed;
				Tab_FullUrl.Visibility = Visibility.Visible;

				// Reimposta i valori iniziali dei campi di inserimento.
				Tb_FullUrl.Text = "";
			}
		}

        private async void Btn_AddQrCode_Click(object sender, RoutedEventArgs e)
        {
			// Chiede all'utente di selezionare l'immagine con il codice qr da analizzare.
			Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
			dlg.Filter = "Image files (*.jpg, *.jpeg, *.png) | *.jpg; *.jpeg; *.png";
			Nullable<bool> result = dlg.ShowDialog();
			if (result == true)
			{
				Tab_QrCodeLoading.Visibility = Visibility.Visible;

				//Carica l'immagine su 'qrserver.com' per essere analizzata.
				Stream stream = await Utils.SendPostImage("http://api.qrserver.com/v1/read-qr-code/", dlg.SafeFileName, File.ReadAllBytes(dlg.FileName));
                StreamReader reader = new StreamReader(stream);
                JArray response = JArray.Parse(reader.ReadToEnd());
				Tab_QrCodeLoading.Visibility = Visibility.Collapsed;

				// Decodifica l'indirizzo URL.
				string[] data = Utils.DecodeTotpUrl((string)(response[0]["symbol"][0]["data"]));

				// Aggiunge il nuovo account all'archivio.
				if (data != null) {
					DateTime currentDate = DateTime.Now;
					string creationDate = String.Format("{0:MM/dd/yyyy}", currentDate);
					if (storage.Add(data[0], data[1], data[2], data[3], data[4], data[5], creationDate)) {
						Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
					} else {
						MessageBox.Show("An error occurred while saving the key!");
					}
				} else {
					MessageBox.Show("The entered code is not valid!");
				}
            }
		}

		private void Btn_AddSecureKey_Click(object sender, RoutedEventArgs e)
		{
			if (!String.IsNullOrEmpty(Tb_KeyLabel.Text) && 
				!String.IsNullOrEmpty(Tb_KeyIssuer.Text) && 
				!String.IsNullOrEmpty(Tb_KeySecret.Text)) {

				// Decodifica l'indirizzo URL.
				string url = _2FACore.generateUrl(Tb_KeyLabel.Text,
					Tb_KeySecret.Text, Tb_KeyIssuer.Text, Cb_KeyAlgorithm.Text, Cb_KeyDigits.Text, Tb_KeyPeriod.Text);
				string[] data = Utils.DecodeTotpUrl(url);

				// Aggiunge il nuovo account all'archivio.
				if (data != null) {
					DateTime currentDate = DateTime.Now;
					string creationDate = String.Format("{0:MM/dd/yyyy}", currentDate);
					if (storage.Add(data[0], data[1], data[2], data[3], data[4], data[5], creationDate)) {
						Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
					} else {
						MessageBox.Show("An error occurred while saving the key!");
					}
				} else {
					MessageBox.Show("The entered code is not valid!");
				}
			} else {
				MessageBox.Show("Fill in all required fields!");
			}
		}

		private void Btn_AddUrl_Click(object sender, RoutedEventArgs e)
        {
			if (!String.IsNullOrEmpty(Tb_FullUrl.Text)) {

				// Decodifica l'indirizzo URL.
				string[] data = Utils.DecodeTotpUrl(Tb_FullUrl.Text);

				// Aggiunge il nuovo account all'archivio.
				if (data != null) {
					DateTime currentDate = DateTime.Now;
					string creationDate = String.Format("{0:MM/dd/yyyy}", currentDate);
					if (storage.Add(data[0], data[1], data[2], data[3], data[4], data[5], creationDate)) {
						Btn_AllKeys.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
					} else {
						MessageBox.Show("An error occurred while saving the key!");
					}
				} else {
					MessageBox.Show("The entered code is not valid!");
				}
			} else {
				MessageBox.Show("Compilare tutti i campi obbligatori!");
			}
		}

		// Import buttons.

		private void Btn_BrowseArchive_Click(object sender, RoutedEventArgs e)
		{
			// Chiede all'utente di selezionare l'archivio da importare.
			Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
			dlg.Filter = "2FA files (*.2fa) | *.2fa";
			Nullable<bool> result = dlg.ShowDialog();
			if (result == true) {
				Btn_BrowseArchive.Content = dlg.SafeFileName;
				importPath = dlg.FileName;
			}
		}

		private void Btn_ImportArchive_Click(object sender, RoutedEventArgs e)
		{
			// Aggiunge il nuovo account all'archivio.
			if (storage.Import(importPath, Tb_ArchivePassword.Password)) {
				MessageBox.Show("The achive was imported successfully.!");
			} else {
				MessageBox.Show("An error occurred during the import!");
			}
		}

		// Export buttons.

		private void Btn_ExportArchive_Click(object sender, RoutedEventArgs e)
		{
			using (var dialog = new System.Windows.Forms.FolderBrowserDialog()) {
				System.Windows.Forms.DialogResult result = dialog.ShowDialog();
				if (result == System.Windows.Forms.DialogResult.OK) {
					if (storage.Export(dialog.SelectedPath)) {
						MessageBox.Show("Archive exported successfully!");
                    }
                }
			}
		}

		// Security buttons.

		private void Btn_ChangePassword_Click(object sender, RoutedEventArgs e)
		{
			if (!String.IsNullOrEmpty(Tb_NewPassword.Password)) {
				if (storage.ChangePassword(Tb_NewPassword.Password)) {
					MessageBox.Show("The password has been successfully changed!");
				}
            } else {
				MessageBox.Show("Fill in all required fields!");
			}
		}

		// Settings buttons.

		private void Btn_SaveSettings_Click(object sender, RoutedEventArgs e)
		{
			// Cambia le impostazioni.
			if (Sw_RequestPassword.IsChecked != true) {
				Properties.Settings.Default.IsAutoLogEnabled = true;
				Properties.Settings.Default.LogPassword = storage.GetPassword();
			} else {
				Properties.Settings.Default.IsAutoLogEnabled = false;
				Properties.Settings.Default.LogPassword = "";
			}

			// Salva le impostazioni.
			Properties.Settings.Default.Save();
			MessageBox.Show("The settings have been successfully saved!");
		}
	}
}