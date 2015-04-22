using System;
using System.Windows.Forms;

namespace Fido_Main
{
  static class Program
  {
    
    [MTAThread]
    static void Main()
    {
      Application.EnableVisualStyles();
      Application.SetCompatibleTextRenderingDefault(false);
      Application.Run(new FidoMain());
    }
    
  }
}
