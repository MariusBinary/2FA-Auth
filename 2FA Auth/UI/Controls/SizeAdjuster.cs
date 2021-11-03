using System.Windows;
using System.Windows.Controls;
using System.Windows.Forms;
using System.Windows.Media;

namespace _2FA_Auth.UI.Controls
{
    public class SizeAdjuster : Decorator
    {
        public SizeAdjuster()
        {
            this.Loaded += (s, e) =>
            {
                Matrix matrix = PresentationSource.FromVisual(this).CompositionTarget.TransformToDevice;
                ScaleTransform scaleTransform = new ScaleTransform(matrix.M11, matrix.M22);

                float height = SystemInformation.VirtualScreen.Height;
                float width = SystemInformation.VirtualScreen.Width;

                if (width <= 1920 && height <= 1080)
                {
                    scaleTransform = new ScaleTransform(1.1 / matrix.M11, 1.1 / matrix.M22);
                    ApplyDPI(scaleTransform);
                    return;
                }
            };
        }

        public void ApplyDPI(ScaleTransform scaleTransform)
        {
            if (scaleTransform.CanFreeze)
                scaleTransform.Freeze();

            this.LayoutTransform = scaleTransform;
        }
    }
}
