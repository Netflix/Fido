/*
*
*  Copyright 2015 Netflix, Inc.
*
*     Licensed under the Apache License, Version 2.0 (the "License");
*     you may not use this file except in compliance with the License.
*     You may obtain a copy of the License at
*
*         http://www.apache.org/licenses/LICENSE-2.0
*
*     Unless required by applicable law or agreed to in writing, software
*     distributed under the License is distributed on an "AS IS" BASIS,
*     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*     See the License for the specific language governing permissions and
*     limitations under the License.
*
*/

using Fido_Main.Main.Detectors;

namespace Fido_Main.Main.Receivers
{
  static class Recieve_API
  {
    //DirectorToEngine is the handler for API based detectors. It is designed
    //to initiate and direct configured APIs to their respective module
    public static void DirectToEngine(string sDetector, string sVendor)
    {
      //todo: This is a really poor attempt at a API redirector
      switch (sDetector)
      {
        case "api":
          switch (sVendor)
          {
            case "cyphortv2":
              Detect_Cyphort_v2.GetCyphortAlerts();
              break;
            case "cyphortv3":
              Detect_Cyphort_v3.GetCyphortAlerts();
              break;
            case "protectwisev1-event":
              Detect_ProtectWise_v1.GetProtectWiseEvents();
              break;
            //case "protectwisev1-observation":
            //  Detect_ProtectWise_v1.GetProtectWiseObservations();
            //  break;
            case "panv1":
              Detect_PaloAlto.GetPANJob();
              break;
            case "carbonblackv1":
              Detect_CarbonBlack.GetCarbonBlackHost(string.Empty,false);
              break;
            case "lastlinev1":
              break;

          }

          break;
      }

    }
  }
}
