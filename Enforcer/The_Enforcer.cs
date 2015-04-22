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

using System.Collections.Generic;
using Fido_Main.Fido_Support.Objects.Fido;

namespace Fido_Main.Enforcer
{
  class The_Enforcer
  {
    public static List<string> RunEnforce(FidoReturnValues lFidoReturnValues)
    { 
      

      return lFidoReturnValues.Actions;
    }

  //  private static bool EnforceBit9(FidoReturnValues lFidoReturnValues)
  //  {
  //    //bool isEnforced = false;
  //    //return isEnforced;
  //  }

  //  private static bool DisableNic(FidoReturnValues lFidoReturnValues)
  //  {
  //    bool isEnforced = false;
  //    return isEnforced;
    
  //  }

  //  private static bool DisableAccount(FidoReturnValues lFidoRetunValues)
  //  {
  //    bool isEnforced = false;
  //    return isEnforced;
    
  //  }

  //  private static bool ResetPassword(FidoReturnValues lFidoReturnValues)
  //  {
  //    bool isEnforced = false;
  //    return isEnforced;
    
  //  }
  }
}
