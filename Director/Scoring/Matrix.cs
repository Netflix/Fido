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
using System.Globalization;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Director.Scoring
{
  internal static class Matrix
  {
    public static FidoReturnValues RunMatrix(FidoReturnValues lFidoReturnValues)
    {
      //Iterate through each detector and the corresponding threat feed looking for values to score
      #region ThreatScore
      Console.WriteLine(@"Starting threat feed evaluation.");
      lFidoReturnValues = Matrix_Scoring.GetDetectorsScore(lFidoReturnValues);

      #endregion

      var isRunAssett = Object_Fido_Configs.GetAsBool("fido.director.assetscore", false);
      if (isRunAssett)
      {
        #region AssetValue
        Console.WriteLine(@"Starting assest evaluation.");
        //asset evaluation
        var isPaired = Object_Fido_Configs.GetAsBool("fido.posture.asset.paired", false);
        lFidoReturnValues = Matrix_Scoring.GetAssetScore(lFidoReturnValues, isPaired);

        #endregion

        #region MachinePosture
        Console.WriteLine(@"Scoring machine posture evaluation.");
        //Patch evaluation
        lFidoReturnValues = Matrix_Scoring.GetPatchScore(lFidoReturnValues);

        //AV evaluation
        lFidoReturnValues = Matrix_Scoring.GetAVScore(lFidoReturnValues);

        #endregion

        #region UserPosture
        Console.WriteLine(@"Starting user posture evaluation.");
        if (lFidoReturnValues.UserInfo != null)
        {
          lFidoReturnValues = Matrix_Scoring.GetUserScore(lFidoReturnValues);
        }

        #endregion
      }

      #region HistoricalInfo
      Console.WriteLine(@"Starting historical artifact evaluation.");
      lFidoReturnValues = Matrix_Historical_Helper.HistoricalEvent(lFidoReturnValues);

      lFidoReturnValues = Matrix_Scoring.GetHistoricalHashCount(lFidoReturnValues);
      lFidoReturnValues = Matrix_Scoring.GetHistoricalURLCount(lFidoReturnValues);
      lFidoReturnValues = Matrix_Scoring.GetHistoricalIPCount(lFidoReturnValues);
      #endregion

      #region PreviousAlerts
      Console.WriteLine(@"Checking to see if this machine has previous alerted.");
      lFidoReturnValues.PreviousAlerts = Matrix_Historical_Helper.GetPreviousMachineAlerts(lFidoReturnValues, true);
      #endregion

      //todo: put configuration in DB for whether to include user/machine score in division of their score.
      //lFidoReturnValues.TotalScore = lFidoReturnValues.TotalScore / 10;
      //lFidoReturnValues.UserScore = lFidoReturnValues.UserScore / 10;
      //lFidoReturnValues.MachineScore = lFidoReturnValues.MachineScore / 10;
      lFidoReturnValues.ThreatScore = lFidoReturnValues.ThreatScore / 10;

      lFidoReturnValues = Matrix_Scoring.SetScoreValues(lFidoReturnValues);

      Console.WriteLine(@"Total Score for event = " + lFidoReturnValues.TotalScore.ToString(CultureInfo.InvariantCulture));
      Console.WriteLine(@"Threat Score for event = " + lFidoReturnValues.ThreatScore.ToString(CultureInfo.InvariantCulture));
      Console.WriteLine(@"Machine Score for event = " + lFidoReturnValues.MachineScore.ToString(CultureInfo.InvariantCulture));
      Console.WriteLine(@"User Score for event = " + lFidoReturnValues.UserScore.ToString(CultureInfo.InvariantCulture));

      return lFidoReturnValues;
    }
  }
}