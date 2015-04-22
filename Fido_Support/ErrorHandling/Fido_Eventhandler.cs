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

using System;
using System.Threading;
using Fido_Main.Fido_Support.Logging;
using Fido_Main.Fido_Support.Objects.Fido;
using Fido_Main.Notification.Email;

namespace Fido_Main.Fido_Support.ErrorHandling
{
  //Error handling class to email errors
  internal static class Fido_EventHandler
  {
    public static void SendEmail(string sErrorSubject, string sErrorMessage)
    {
      var isGoingToRun = Object_Fido_Configs.GetAsBool("fido.email.runerroremail", false);
      var sErrorEmail = Object_Fido_Configs.GetAsString("fido.email.erroremail", null);
      var sFidoEmail = Object_Fido_Configs.GetAsString("fido.email.fidoemail", null);
      var isTest = Object_Fido_Configs.GetAsBool("fido.application.teststartup", true);

      if (!isGoingToRun) return;
      if (isTest) sErrorSubject = "Test: " + sErrorSubject;


      Logging_Fido.RunLogging(sErrorMessage);
      Email_Send.Send(sErrorEmail, sFidoEmail, sFidoEmail, sErrorSubject, sErrorMessage, null, null);
      Console.WriteLine(sErrorMessage);
      Thread.Sleep(1000);
    }
  }
}
