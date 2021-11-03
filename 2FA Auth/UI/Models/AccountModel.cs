using System.ComponentModel;
using System.Linq;
using System.Windows.Media.Imaging;
using _2FA_Auth.Core;

namespace _2FA_Auth.UI.Models
{
    public class AccountModel : INotifyPropertyChanged
    {
        public int _id = -1; 
        public int Id
        {
            get { return _id; }
            set
            {
                _id = value;
                RaisePropertyChanged("Id");
            }
        }

        public string Image { 
            get
            {
                string[] issuers = new string[] { 
                    "amazon", 
                    "apple", 
                    "aws", 
                    "blizzard",
                    "cloudflare",
                    "discord",
                    "facebook",
                    "github", 
                    "google", 
                    "instagram",
                    "paypal",
                    "reddit", 
                    "rockstar_games",
                    "teamviewer" 
                };

                if (issuers.Contains(Issuer.ToLower().Replace(" ", "_"))) {
                    return @"/2FA Auth;component/Images/acc_" + Issuer.ToLower().Replace(" ", "_") + ".png";
                } else {
                    return @"/2FA Auth;component/Images/acc_default.png";
                }
            }
        }

        public string Label { get; set; }
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Algorithm { get; set; }
        public string Digits { get; set; }
        public string Period { get; set; }
        public string Date { get; set; }

        public string Url
        {
            get
            {
                return _2FACore.generateUrl(Label, Secret, Issuer, Algorithm, Digits, Period);
            }
        }

        private BitmapImage _qrCode = null;
        public BitmapImage QrCode
        {
            get { return _qrCode; }
            set
            {
                _qrCode = value;
                RaisePropertyChanged("QrCode");
            }
        }

        private string _code = "";
        public string Code
        {
            get { return _code; }
            set
            {
                _code = value;
                RaisePropertyChanged("Code");
            }
        }

        private double _value = 0;
        public double Value
        {
            get { return _value; }
            set
            {
                _value = value;
                RaisePropertyChanged("Value");
            }
        }

        private bool _isActived = false;
        public bool IsActived
        {
            get { return _isActived; }
            set
            {
                _isActived = value;
                RaisePropertyChanged("IsActived");

                if (_isActived == true && QrCode == null) {
                    QrCode = _2FACore.generateQrCode(Label, Secret, Issuer, Algorithm, Digits, Period);
                }
            }
        }

        #region INotifyPropertyChanged Members

        public event PropertyChangedEventHandler PropertyChanged;
        protected void RaisePropertyChanged(string name)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
        }

        #endregion
    }
}
