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
using System.Collections.Generic;

namespace Fido_Main.Fido_Support.Objects.VirusTotal
{
  public class Object_VirusTotal_IP
  {
    public class IPReport
    {
      public List<DetectedURLs> DetectedUrls { get; set; }
      public List<Samples> UndetectedDownloadedSamples { get; set; }
      public List<Samples> DetectedCommunicatingSamples { get; set; }
      public List<Samples> UndetectedCommunicatingSamples { get; set; }
      public List<Samples> DetectedDownloadedSamples { get; set; }
      public List<Resolved> Resolutions { get; set; }
      public string VerboseMsg { get; set; }
    }

    public class Resolved
    {
      public string LastResolved { get; set; }
      public string Hostname { get; set; }
    }

    public class DetectedURLs
    {
      public string URL { get; set; }
      public int Positives { get; set; }
      public int Total { get; set; }
      public DateTime ScanDate { get; set; }
    }

    public class Samples
    {
      public DateTime Date { get; set; }
      public int Positives { get; set; }
      public int Total { get; set; }
      public string Sha256 { get; set; }
    }
  }
}
