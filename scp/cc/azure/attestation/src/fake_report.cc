/*
 * Portions Copyright (c) Microsoft Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "attestation.h"

namespace google::scp::azure::attestation {

std::optional<AttestationReport> fetchFakeSnpAttestation() {
  return AttestationReport{
      // Evidence
      "AgAAAAIAAAAfAAMAAAAAAAEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAEA"
      "AAADAAAAAAAI0gEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsOw1b8dJW+"
      "k47Xe78B7Vf8vcCkIXtNQ9glZFAoaUfExB1O6WrLAOgU2scDBk69HT0RIxn88jfyN6KXjcSX"
      "YB9rcxB8GzyP2FdvVLux3fRCBLO9VZ+eO/KBz/"
      "eiJSxgOqu87VghAkMZHgrWtU2vPED0ZSRSyKcqsXFQIr86R/"
      "IYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC76j4Cd"
      "AnTfrWAxZAaBHUBSCMnekwrkur1innnjjqhHv///////////////////////////////////"
      "///////"
      "AwAAAAAACHMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADcfjfMm5W00HLsTG68q+"
      "r5imZVsuaSdo+et54P4fqdbHCx0KJRdX3NSLNg1mD4m78ijvn5kAMBTG1TSmgUc+"
      "oHAwAAAAAACHMENAEABDQBAAMAAAAAAAhzAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuU7THp0vh0SIcHW94ShZ8YwgXYcM7A"
      "5Oe9XXKdeEJpwQm7RNqX/"
      "1a8NOjmrzYS0yAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA100HVbSEoK/tifyXvY7Br+k7UN/"
      "CIDBE/"
      "c+LYoInHSAzIphkFdIQf3H5oACyEAv+"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAA=",
      // Endorsements
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZURENDQXZ1Z0F3SUJBZ0lCQURCR0Jn"
      "a3Foa2lHOXcwQkFRb3dPYUFQTUEwR0NXQ0dTQUZsQXdRQ0FnVUEKb1J3d0dnWUpLb1pJaHZj"
      "TkFRRUlNQTBHQ1dDR1NBRmxBd1FDQWdVQW9nTUNBVENqQXdJQkFUQjdNUlF3RWdZRApWUVFM"
      "REF0RmJtZHBibVZsY21sdVp6RUxNQWtHQTFVRUJoTUNWVk14RkRBU0JnTlZCQWNNQzFOaGJu"
      "UmhJRU5zCllYSmhNUXN3Q1FZRFZRUUlEQUpEUVRFZk1CMEdBMVVFQ2d3V1FXUjJZVzVqWldR"
      "Z1RXbGpjbThnUkdWMmFXTmwKY3pFU01CQUdBMVVFQXd3SlUwVldMVTFwYkdGdU1CNFhEVEl6"
      "TURFeE5URTBNRFl6TVZvWERUTXdNREV4TlRFMApNRFl6TVZvd2VqRVVNQklHQTFVRUN3d0xS"
      "VzVuYVc1bFpYSnBibWN4Q3pBSkJnTlZCQVlUQWxWVE1SUXdFZ1lEClZRUUhEQXRUWVc1MFlT"
      "QkRiR0Z5WVRFTE1Ba0dBMVVFQ0F3Q1EwRXhIekFkQmdOVkJBb01Ga0ZrZG1GdVkyVmsKSUUx"
      "cFkzSnZJRVJsZG1salpYTXhFVEFQQmdOVkJBTU1DRk5GVmkxV1EwVkxNSFl3RUFZSEtvWkl6"
      "ajBDQVFZRgpLNEVFQUNJRFlnQUVZdElnNUQ2dlErajljQVRPYkd1dkhGa1lqU05ma3JLNXJI"
      "WHJUdEJUTnJXMjhDMkFxTFJsCkZpRDcrT0daRTJxa3UyVFVtUlM5cHhxbUNKM2pGK0NDMXZG"
      "OXg2UmF5dXVqVnA4Z0VGTWwzU0cvaFZwZjJCZzMKaWorYVFiZUhqUHgrbzRJQkZqQ0NBUkl3"
      "RUFZSkt3WUJCQUdjZUFFQkJBTUNBUUF3RndZSkt3WUJCQUdjZUFFQwpCQW9XQ0UxcGJHRnVM"
      "VUl3TUJFR0Npc0dBUVFCbkhnQkF3RUVBd0lCQXpBUkJnb3JCZ0VFQVp4NEFRTUNCQU1DCkFR"
      "QXdFUVlLS3dZQkJBR2NlQUVEQkFRREFnRUFNQkVHQ2lzR0FRUUJuSGdCQXdVRUF3SUJBREFS"
      "QmdvckJnRUUKQVp4NEFRTUdCQU1DQVFBd0VRWUtLd1lCQkFHY2VBRURCd1FEQWdFQU1CRUdD"
      "aXNHQVFRQm5IZ0JBd01FQXdJQgpDREFSQmdvckJnRUVBWng0QVFNSUJBTUNBWE13VFFZSkt3"
      "WUJCQUdjZUFFRUJFRGNmamZNbTVXMDBITHNURzY4CnErcjVpbVpWc3VhU2RvK2V0NTRQNGZx"
      "ZGJIQ3gwS0pSZFgzTlNMTmcxbUQ0bTc4aWp2bjVrQU1CVEcxVFNtZ1UKYytvSE1FWUdDU3FH"
      "U0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJna3Foa2lHOXcwQgpB"
      "UWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFCZ0NJWlZHR2VyUFNG"
      "RExwQXBPSDBQCmVyYVRndUhOb2cwQ29qcloyMWc1QnBwcm0zaG5ZMUNYMVcwaTBKVEJ1YTRt"
      "a1hsTmVGdHc5THRoOFlPNVdmUW0KQ1RnamdCcWovQXJ3U2xtbGFxcDI0QVVIVll3dlVxcXls"
      "clp4L2pBMFo3TmdPY0FiZmFFNXhDNWFZOTFPTTFNRwpDSDkxY3A3SW9ZT2dYY0lMaVZ6dmdT"
      "R25hQXpvd2VJbVozbVRETVZTanorekpLbUZIRGFQbENZN1E5b3N4Y0syCjdrcHQ0WjEzN3RJ"
      "c2VLTzM0TXo1c1NvYzk2bTExeCtZaE9LbjBseWoxdnlMdnN4OWdLZDdDM01RbnVKZ1pqd2oK"
      "Q1lkYzhzRlZFdGJ4MU45azd6c3JSUUpMQ0sxdkMrVnd5T0RsYnY1dFBuK0duV1B0ZEhVcHZu"
      "VFp1czFmKzlFWAo4aGhoY1lFeHdWcFh5SVB4b29lMVhHZ2E5NXpHYVA5dWFJM2tPcXNDeDVY"
      "VmxiMms4YytFbncxK0ZKcUlSZFk1Ci96b3VVa0pqbGYxci9Bb0FpaEhBTmM2QkpucDIzZkFu"
      "RGVTVEJWT28vaXhJeFFISjRKaXRGMFNLTzdBVFI2QmoKOGM3QjFXZnNBdHoyeWFRelNLbG5R"
      "a2liVzJrbGQ1OHUyNmkwS29ZSmxROHhaYktnV0krZVh1NTF6cTFqejR0dQpsRHdCcUN2WEJU"
      "emZuYXlpMFM3Z3E2QUFETHo1TDRqK2xOTnJtaHpaSTZDRWxudHFYeWV5RmNVYXI5QnptQ3gy"
      "CklpeUt2bkRIWXV0MnpaRFh6enN2Z3ljN0VlSmVpcGE3VXBrU1NyZE54b3F3bEgwSlRCYUpv"
      "NlFFcG5TY2JkamwKSENuUUhKMVBPWHlMbnJoc0xqU3A5Zz09Ci0tLS0tRU5EIENFUlRJRklD"
      "QVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdpVENDQkRpZ0F3SUJB"
      "Z0lEQVFBQk1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFDaEhE"
      "QWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJNSHN4"
      "RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1CSUdB"
      "MVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFRS0RC"
      "WkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0VFds"
      "c1lXNHdIaGNOTWpBeE1ESXlNVGd5TkRJd1doY05ORFV4TURJeQpNVGd5TkRJd1dqQjdNUlF3"
      "RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJnTlZC"
      "QWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dXUVdS"
      "MllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKVTBWV0xVMXBiR0Z1"
      "TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBblUyZHJyTlRm"
      "YmhOUUlsbGYrVzJ5K1JPQ2JTeklkMWFLWmZ0CjJUOXpqWlFPempHY2NsMTdpMW1JS1dsN05U"
      "Y0IwVllYdDNKeFpTek9aanNqTE5WQUVOMk1HajlUaWVkTCtRZXcKS1pYMEptUUV1WWptK1dL"
      "a3NMdHhnZExwOUU3RVpOd05EcVYxcjBxUlA1dEI4T1dreVFiSWRMZXU0YUN6N2ovUwpsMUZr"
      "Qnl0ZXY5c2JGR3p0N2N3bmp6aTltN25vcXNrK3VSVkJwMytJbjM1UVBkY2o4WWZsRW1uSEJO"
      "dnVVREpoCkxDSk1XOEtPalA2KytQaGJzM2lDaXRKY0FORXRXNHFUTkZvS1czQ0hsYmNTQ2pU"
      "TThLc05iVXgzQThlazVFVkwKalpXSDFwdDlFM1RmcFI2WHlmUUtuWTZrbDVhRUlQd2RXM2VG"
      "WWFxQ0ZQcklvOXBRVDZXdURTUDRKQ1lKYlpuZQpLS0liWmp6WGtKdDNOUUczMkV1a1lJbUJi"
      "OVNDa205K2ZTNUxaRmc5b2p6dWJNWDMrTmtCb1NYSTdPUHZuSE14Cmp1cDltdzVzZTZRVVY3"
      "R3FwQ0EyVE55cG9sbXVRK2NBYXhWN0pxSEU4ZGw5cFdmK1kzYXJiKzlpaUZDd0Z0NGwKQWxK"
      "dzVEMENUUlRDMVk1WVdGREJDckEvdkdubVRucUc4QytqalVBUzdjampSOHE0T1BoeURtSlJQ"
      "bmFDL1pHNQp1UDBLMHo2R29PLzN1ZW45d3FzaEN1SGVnTFRwT2VIRUpSS3JRRnI0UFZJd1ZP"
      "QjArZWJPNUZnb3lPdzQzbnlGCkQ1VUtCRHhFQjRCS28vMHVBaUtITFJ2dmdMYk9SYlU4S0FS"
      "SXMxRW9xRWptRjhVdHJtUVdWMmhVand6cXd2SEYKZWk4clB4TUNBd0VBQWFPQm96Q0JvREFk"
      "QmdOVkhRNEVGZ1FVTzhadUdDckQvVDFpWkVpYjQ3ZEhMTFQ4di9ndwpId1lEVlIwakJCZ3dG"
      "b0FVaGF3YTBVUDN5S3hWMU1VZFFVaXIxWGhLMUZNd0VnWURWUjBUQVFIL0JBZ3dCZ0VCCi93"
      "SUJBREFPQmdOVkhROEJBZjhFQkFNQ0FRUXdPZ1lEVlIwZkJETXdNVEF2b0MyZ0s0WXBhSFIw"
      "Y0hNNkx5OXIKWkhOcGJuUm1MbUZ0WkM1amIyMHZkbU5sYXk5Mk1TOU5hV3hoYmk5amNtd3dS"
      "Z1lKS29aSWh2Y05BUUVLTURtZwpEekFOQmdsZ2hrZ0JaUU1FQWdJRkFLRWNNQm9HQ1NxR1NJ"
      "YjNEUUVCQ0RBTkJnbGdoa2dCWlFNRUFnSUZBS0lECkFnRXdvd01DQVFFRGdnSUJBSWdlVVFT"
      "Y0FmM2xEWXFnV1UxVnRsRGJtSU44UzJkQzVrbVF6c1ovSHRBalFuTEUKUEkxamgzZ0piTHhM"
      "NmdmM0s4anhjdHpPV25rWWNiZGZNT09yMjhLVDM1SWFBUjIwcmVrS1JGcHRUSGhlK0RGcgoz"
      "QUZ6WkxERDdjV0syOS9HcFBpdFBKREtDdkk3QTRVZzA2cms3SjB6QmUxZnovcWU0aTIvRjEy"
      "cnZmd0NHWWhjClJ4UHk3UUYzcThmUjZHQ0pkQjFVUTVTbHdDakZ4RDR1ZXpVUnp0SWxJQWpN"
      "a3Q3REZ2S1JoKzJ6Sys1cGxWR0cKRnNqREp0TXoydWQ5eTBwdk9FNGozZEg1SVc5akd4YVNH"
      "U3RxTnJhYm5ucEYyMzZFVHIxL2E0M2I4RkZLTDVRTgptdDhWcjl4blhScHpucUNSdnFqcitr"
      "VnJiNmRsZnVUbGxpWGVRVE1sQm9SV0ZKT1JMOEFjQkp4R1o0SzJtWGZ0CmwxalU1VExlaDVL"
      "WEw5Tlc3YS9xQU9JVXMyRmlPaHFydHpBaEpSZzlJajhRa1E5UGsrY0tHenc2RWwzVDNrRnIK"
      "RWc2emt4bXZNdWFiWk9zZEtmUmtXZmhIMlpLY1RsRGZtSDFIMHpxMFEyYkczdXZhVmRpQ3RG"
      "WTFMbFd5QjM4SgpTMmZOc1IvUHk2dDVickVKQ0ZOdnphRGt5NktlQzRpb24vY1ZnVWFpN3p6"
      "UzNiR1FXektES1UzNVNxTlUyV2tQCkk4eENaMDBXdElpS0tGblhXVVF4dmxLbW1nWkJJWVBl"
      "MDF6RDBOOGF0RnhtV2lTbmZKbDY5MEI5ckpwTlIvZkkKYWp4Q1czU2Vpd3M2cjFabSt0Q3VW"
      "Yk1pTnRwUzlUaGpOWDR1dmU1dGh5ZkUyRGdveFJGdlkxQ3NvRjVNCi0tLS0tRU5EIENFUlRJ"
      "RklDQVRFLS0tLS0KLS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUdZekNDQkJLZ0F3"
      "SUJBZ0lEQVFBQU1FWUdDU3FHU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUMKQlFD"
      "aEhEQWFCZ2txaGtpRzl3MEJBUWd3RFFZSllJWklBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJN"
      "SHN4RkRBUwpCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUXN3Q1FZRFZRUUdFd0pWVXpFVU1C"
      "SUdBMVVFQnd3TFUyRnVkR0VnClEyeGhjbUV4Q3pBSkJnTlZCQWdNQWtOQk1SOHdIUVlEVlFR"
      "S0RCWkJaSFpoYm1ObFpDQk5hV055YnlCRVpYWnAKWTJWek1SSXdFQVlEVlFRRERBbEJVa3N0"
      "VFdsc1lXNHdIaGNOTWpBeE1ESXlNVGN5TXpBMVdoY05ORFV4TURJeQpNVGN5TXpBMVdqQjdN"
      "UlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFTE1Ba0dBMVVFQmhNQ1ZWTXhGREFTCkJn"
      "TlZCQWNNQzFOaGJuUmhJRU5zWVhKaE1Rc3dDUVlEVlFRSURBSkRRVEVmTUIwR0ExVUVDZ3dX"
      "UVdSMllXNWoKWldRZ1RXbGpjbThnUkdWMmFXTmxjekVTTUJBR0ExVUVBd3dKUVZKTExVMXBi"
      "R0Z1TUlJQ0lqQU5CZ2txaGtpRwo5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBMExkNTJS"
      "Sk9kZWlKbHFLMkpkc1ZtRDdGa3R1b3RXd1gxZk5nClc0MVhZOVh6MUhFaFNVbWhMejlDdTlE"
      "SFJsdmdKU054YmVZWXNuSmZ2eWp4MU1mVTBWNXRrS2lVMUVlc05GdGEKMWtUQTBzek5pc2RZ"
      "Yzlpc3FrN21YVDUrS2ZHUmJmYzRWLzl6UkljRThqbEhONjFTMWp1OFg5Mys2ZHhEVXJHMgpT"
      "enhxSjRCaHF5WW1VRHJ1UFhKU1g0dlVjMDFQN2o5OE1wcU9TOTVyT1JkR0hlSTUyTmF6NW0y"
      "QitPK3Zqc0MwCjYwZDM3alk5TEZldU9QNE1lcmk4cWdmaTJTNWtLcWcvYUY2YVB0dUFaUVZS"
      "N3UzS0ZZWFA1OVhtSmd0Y29nMDUKZ21JMFQvT2l0TGh1elZ2cFpjTHBoMG9kaC8xSVBYcXgz"
      "K01uakQ5N0E3ZlhwcUdkL3k4S3hYN2prc1RFekFPZwpiS0FlYW0zbG0rM3lLSWNUWU1sc1JN"
      "WFBjak5iSXZtc0J5a0QvL3hTbml1c3VIQmtnbmxFTkVXeDFVY2JRUXJzCitnVkRrdVZQaHNu"
      "eklSTmdZdk00OFkrN0xHaUpZbnJtRTh4Y3JleGVrQnhydmEyVjlUSlFxbk4zUTUza3Q1dmkK"
      "UWkzK2dDZm1rd0MwRjB0aXJJWmJMa1hQclB3elowTTllTnhoSXlTYjJucEpmZ25xejU1STB1"
      "MzN3aDRyMFpOUQplVEdmdzAzTUJVdHl1ekdlc0drY3crbG9xTWFxMXFSNHRqR2JQWXhDdnBD"
      "cTcrT2dwQ0NvTU5pdDJ1TG85TTE4CmZIejEwbE9NVDhuV0FVdlJaRnp0ZVhDbSs3UEhkWVBs"
      "bVF3VXczTHZlbkovSUxYb1FQSGZia0gwQ3lQZmhsMWoKV2hKRlphc0NBd0VBQWFOK01Id3dE"
      "Z1lEVlIwUEFRSC9CQVFEQWdFR01CMEdBMVVkRGdRV0JCU0ZyQnJSUS9mSQpyRlhVeFIxQlNL"
      "dlZlRXJVVXpBUEJnTlZIUk1CQWY4RUJUQURBUUgvTURvR0ExVWRId1F6TURFd0w2QXRvQ3VH"
      "CktXaDBkSEJ6T2k4dmEyUnphVzUwWmk1aGJXUXVZMjl0TDNaalpXc3ZkakV2VFdsc1lXNHZZ"
      "M0pzTUVZR0NTcUcKU0liM0RRRUJDakE1b0E4d0RRWUpZSVpJQVdVREJBSUNCUUNoSERBYUJn"
      "a3Foa2lHOXcwQkFRZ3dEUVlKWUlaSQpBV1VEQkFJQ0JRQ2lBd0lCTUtNREFnRUJBNElDQVFD"
      "Nm0wa0RwNnp2NE9qZmd5K3psZWVoc3g2b2wwb2NnVmVsCkVUb2JweCtFdUNzcVZGUlBLMWpa"
      "MXNwL2x5ZDkrMGZRMHI2Nm43a2FnUms0Q2EzOWc2NldHVEpNZUpkcVlyaXcKU1RqakRDS1ZQ"
      "U2VzV1hZUFZBeURobVA1bjJ2K0JZaXBaV2hwdnFwYWlPK0VHSzVJQlArNTc4UWVXL3NTb2ty"
      "SwpkSGFMQXhHMkxoWnhqOWFGNzNmcUM3T0FKWjVhUG9udzRSRTI5OUZWYXJoMVR4MmVUM3dT"
      "Z2tEZ3V0Q1RCMVlxCnpUNUR1d3ZBZStjbzJDSVZJek1EYW1ZdVNGalBOMEJDZ29qbDdWK2JU"
      "b3U3ZE1zcUl1L1RXL3JQQ1g5L0VVY3AKS0dLcVBRM1ArTjlyMWhqRUZZMXBsQmc5M3Q1M09P"
      "bzQ5R05JK1YxenZYUExJNnhJRlZzaCttdG8yUnRnRVgvZQpwbU1LVE5ONnBzVzg4cWc3YzFo"
      "VFd0TjZNYlJ1UTB2bStPKy8ydEtCRjJoOFRIYjk0T3Z2SEhvRkRwYkNFTGxxCkhuSVloeHkw"
      "WUtYR3lhVzFOamZVTHhycm14Vlc0d2NuNUU4R2RkbXZOYTZ5WW04c2NKYWdFaTEzbWhHdTRK"
      "cWgKM1FVM3NmOGlVU1VyMDl4UUR3SHRPUVVWSXF4NG1hQlpQQnRTTWYrcVVEdGpYU1NxOGxm"
      "V2NkOGJMcjltZHNVbgpKWkowK3R1UE1LbUJuU0g4NjBsbEtrK1ZwVlFzZ3FiekRJdk9MdkQ2"
      "VzFVbXEyNWJveENZSitUdUJvYTRzK0hICkNWaUF2Z1Q5a2YvckJxMWQraXZqNnNra0h4dXpj"
      "eGJrMXh2NlpHeHJ0ZUp4Vkg3S2xYN1lSZFo2ZUFSS3dMZTQKQUZaRUF3b0tDUT09Ci0tLS0t"
      "RU5EIENFUlRJRklDQVRFLS0tLS0K",
      // UVM Endorsements
      "0oRZE86nATglA3BhcHBsaWNhdGlvbi9qc29uGCGDWQZvMIIGazCCBFOgAwIBAgITMwAAABxx"
      "pnEfWQZPEAAAAAAAHDANBgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJVUzEeMBwGA1UEChMV"
      "TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgU0NEIFByb2R1Y3Rz"
      "IFJTQSBDQTAeFw0yMzEwMTkyMDAwMjdaFw0yNDEwMTYyMDAwMjdaMGwxCzAJBgNVBAYTAlVT"
      "MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy"
      "b3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAMTDUNvbnRhaW5lclBsYXQwggGiMA0GCSqGSIb3"
      "DQEBAQUAA4IBjwAwggGKAoIBgQDDs97+"
      "QnO9QUmRY8N09HSAWzHw8fbXbwQYzBW5qiIMnBFVcWC2aC0g239fcl+/"
      "ubt6p3A1xW75zaMmvibFPK/iUxKiJtek7kZdDD0PI2eoL/"
      "EmPBL0OLJwSb8NzKJbva+dSXndYjidTCOSBT7f862RBNF/"
      "TmidfPl6Qte59Yim5RZ+VyDGOG2Sr3qY0oiD+"
      "lzE4ZCJNtdfi8SVGXjY9VHXLKReoU1eHNtqTO6iRSk0R4VKIKfao1l4b10XM9UfuKm0O96QH"
      "wYNRDydqBivQ8Yr2HILgsKvk1lxyt6DIlUX5RsHZgpMM2CrphXQ83vRt6//"
      "BqZFkz30VD1LKGJs/"
      "IcY7hS5qgYZAakulz1KWUBQuihQ2IZeIcQVuJ2MAxGX3MsW8NkFCalZTMPlN/"
      "IBd0Pwb95MwT/"
      "kP4hVNjREHZBxxpOx4lXqkrAtQ3RvvtjmVxdUDGxLIgCCIx2g0eMIRS6ghIwaEN2ldk3nOsB"
      "bQu6qxlyq/+H4GwW1XeuUYi8yEJECAwEAAaOCAZswggGXMA4GA1UdDwEB/"
      "wQEAwIHgDAjBgNVHSUEHDAaBgsrBgEEAYI3TDsBAQYLKwYBBAGCN0w7AQIwHQYDVR0OBBYEF"
      "PXTTQJXWkUWD7uFNOULaC+qbyhHMEUGA1UdEQQ+"
      "MDykOjA4MR4wHAYDVQQLExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ3Mjk3"
      "Mis1MDE2MDUwHwYDVR0jBBgwFoAUVc1NhW7NSjXDjj9yAbqqmBmXS6cwXgYDVR0fBFcwVTBT"
      "oFGgT4ZNaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIw"
      "U0NEJTIwUHJvZHVjdHMlMjBSU0ElMjBDQS5jcmwwawYIKwYBBQUHAQEEXzBdMFsGCCsGAQUF"
      "BzAChk9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUy"
      "MFNDRCUyMFByb2R1Y3RzJTIwUlNBJTIwQ0EuY3J0MAwGA1UdEwEB/"
      "wQCMAAwDQYJKoZIhvcNAQEMBQADggIBAHaZyKfQ+"
      "0uXl79Y8tgT3eOzDnKhupIdqw4Gw56vT7FuQM0v+/klkLXVS/"
      "lDQ0UOIZCVOYF21hEKl5F5l/XORPRs0XMtuHi9VFUq4x/"
      "I0r7692vykPY6NdUZWCsySzaWfr6db/nvJx11w/"
      "bWsljCKvQ5xnKH+d1jCbf5SoJbYLjiyGXue85X0So334BOG5+"
      "sFf7iVl3UUuM8d2cccSWXaarjjVXxw44vImFEU+"
      "1W0iQSdkxojL0uFPNA3MjQNlkG2Wf4xAS6S+m6dIz380UW6Ax8c5Kivnt+tnIKkvpz9mHY+"
      "grp98Lrmg5JsQLN7oSdXiIe0EGP5DudUpPpOWN32npHYnDzecR+NLapAyXmoS/"
      "EG01Fhq4fVUp+PyGr36YjnvBI297g92f6h1NtSiJel1WIAxVXYWPo8d/3YVVlM/"
      "8pDJBWCTdt+CBGGKQ3ogfSESkHsVmStjM/"
      "ItOgu1iC51jQFDwhxxF80V2sqKPx7PA+"
      "Ftt1oYkHy08E8rU65djZm6dtbVsq7QZDaFmpIpABs7yT3YOMuW3B++"
      "Rz1QOHVF2M3sDmb1KXyaX2S89khSZHaSVlpxWjKl4c/"
      "b1sIQiIo1XDkMoQj8DndejbNpIRIUHTgS7B3PyLKbBw8DNQLKImbFlJMeXdiVD77bTAR0nmL"
      "rMY3UNABISI0NE19NK/30eiWQbVMIIG0TCCBLmgAwIBAgITMwAAAAOVhEf/"
      "iehmCQAAAAAAAzANBgkqhkiG9w0BAQwFADBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWlj"
      "cm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJT"
      "QSBSb290IENBIDIwMjIwHhcNMjIwMjE3MDA0NTIzWhcNNDIwMjE3MDA1NTIzWjBVMQswCQYD"
      "VQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNy"
      "b3NvZnQgU0NEIFByb2R1Y3RzIFJTQSBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC"
      "ggIBAKvtf7VxvoxzvvHXyp3xAdZ0h7yMQpNMn8qVdGtOR+pyhLWkFsGMQlTXDe2Yes+"
      "o7mC0IEQJMz39CJxIjG6XYIQfcF2CaO/6MCzWzysbFvlTkoY/LN/g0/RlcJ/"
      "IdFlf0VWcvujpZPh9CLlEd0HS9qYFRAPRRQOvwe3NT5uEd38fRbKbZ6vCJG2c/"
      "YxHByKbeooYReovPoNpVpxdaIDS64IdgGl8mX+yTPwwwLHOfR+E2UWgnnQqgNYp0hCM2YZ+"
      "J5zU0QZCwZ1JMLXQ9eK0sJW3uPfj7iA/"
      "k1k57kN3dSZ4P4hkqGVTAnrBzaoZsINMkGVJbgEpfSPrRLBOkr4Zmh7m8PigL8B8xIJ01Tx1"
      "KBmfiWAFGmVx++NSY8oFxRW/"
      "DdKdwWLr5suCpB2ONjF7LNv4A5v4SZ+zYCwpTc8ouxPPUtZSG/"
      "fklVEFveW30jMJwQAf29X8wAuJ0pwuWaP2PziQSonR4VmRP3cKz88aAbm0zmzvx+"
      "pdTCX9fH/cTuYwErjJA3d9G7/3sDGE/QBqkjC+NkZI8XCdm6Ur8QIK4LaZJ/"
      "ZBT9QEkXF7xML0FBe3YLYWk5F2pc4d2wJinZIFvJJvLvkAp//"
      "guabt6wCXTjxHDz2RkiJnmiteSLO09DeQIvgEGY7nJTKy1oMwRoalGrL14YD4QyNawcazBtG"
      "ZQ20NAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYBBAGCNxUBBAMCAQAwHQY"
      "DVR0OBBYEFFXNTYVuzUo1w44/"
      "cgG6qpgZl0unMBEGA1UdIAQKMAgwBgYEVR0gADAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMA"
      "QTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFAuzaDuv2q/"
      "ucKV22SH3zEQWB9D4MGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly93d3cubWljcm9zb2Z0LmN"
      "vbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFN1cHBseSUyMENoYWluJTIwUlNBJTIwUm9vdCU"
      "yMENBJTIwMjAyMi5jcmwweQYIKwYBBQUHAQEEbTBrMGkGCCsGAQUFBzAChl1odHRwOi8vd3d"
      "3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFN1cHBseSUyMENoYWl"
      "uJTIwUlNBJTIwUm9vdCUyMENBJTIwMjAyMi5jcnQwDQYJKoZIhvcNAQEMBQADggIBAG/"
      "eYdZr+kG/"
      "bRyUyOGKw8qn9DME5Ckmz3vmIdcmdU+"
      "LE3TnFzEBRo1FRF1tdOdqCq58vtH5luxa8hkl4wyvvAjv0ahppr+"
      "2UI79vyozKGIC4ud2zBpWgtmxifFv5KyXy7kZyrvuaVDmR3hwAhpZyTfS6XLxdRnsDlsD95q"
      "dw89hBKf8l/"
      "QfFhCkPJi3BPftb0E1kFQ5qUzl4jSngCKyT8fdXZBRdHlHil11BJpNm7gcJxJQfYWBX+"
      "EDRpNGS0YI5/"
      "cQhMES35jYJfGGosw9DFCfORzjRmc1zpEVXUrnbnJDtcjrpeQz0DQg6KVwOjSkEkvjzKltH0"
      "+bnU1IKvrSuVy8RFWci1vdrAj0I6Y2JaALcE00Lh86BHGYVK/"
      "NZEZQAAXlCPRaOQkcCaxkuT0zNZB0NppU1485jHR67p78bbBpXSe9LyfpWFwB3q6jye9KW2u"
      "Xi/7zTPYByX0AteoVo6JW56JXhILCWmzBjbj8WUzco/"
      "sxjwbthT0WtKDADKuKREahCy0tSestD3D5XcGIdMvU9BBLFglXtW2LmdTDe4lLBSuuS2TQoF"
      "Bw/BoqXctCe/"
      "sDer5TVxeZ4h7zU50vcrCV74x+xCI4XpUmXI3uyLrhEVJh0C03L3pE+NTmIIm+"
      "7Zk8q5MmrkQ7pVwkJdT7cW7YgiqkoCIOeygb/"
      "UVPXxhWWQWzMIIFrzCCA5egAwIBAgIQaCjVTH5c2r1DOa4MwVoqNTANBgkqhkiG9w0BAQwFA"
      "DBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTAwLgYDV"
      "QQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb290IENBIDIwMjIwHhcNMjIwMjE3M"
      "DAxMjM2WhcNNDcwMjE3MDAyMTA5WjBfMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb"
      "2Z0IENvcnBvcmF0aW9uMTAwLgYDVQQDEydNaWNyb3NvZnQgU3VwcGx5IENoYWluIFJTQSBSb"
      "290IENBIDIwMjIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCeJQFmGR9kNMGdO"
      "SNiHXGLVuol0psf7ycBgr932JQzgxhIm1Cee5ZkwtDDX0X/"
      "MpzoFxe9eO11mF86BggrHDebRkqQCrCvRpI+M4kq+rjnMmPzI8du0hT7Jlju/"
      "gaEVPrBHzeq29TsViq/"
      "Sb3M6wLtxk78rBm1EjVpFYkXTaNo6mweKZoJ8856IcYJ0RnqjzBGaTtoBCt8ii3WY13qbdY5"
      "nr0GPlvuLxFbKGunUqRoXkyk6q7OI79MNnHagUVQjsqGzv9Tw7hDsyTuB3qitPrHCh17xlI1"
      "MewIH4SAklv4sdo51snn5YkEflF/9OZqZEdJ6vjspvagQ1P+2sMjJNgl2hMsKrc/"
      "lN53HEx4HGr5mo/rahV3d61JhM4QQMeZSA/"
      "Vlh6AnHOhOKEDb9NNINC1Q+T3LngPTve8v2XabZALW7/"
      "e6icnmWT4OXxzPdYh0u7W81MRLlXD3OrxKVfeUaF4c5ALL/XJdTbrjdJtjnlduho4/"
      "98ZAajSyNHW8uuK9S7RzJMTm5yQeGVjeQTE8Z6fjDrzZAz+"
      "mB2T4o9WpWNTI7hucxZFGrb3ew/NpDL/"
      "Wv6WjeGHeNtwg6gkhWkgwm0SDeV59ipZz9ar54HmoLGILQiMC7HP12w2r575A2fZQXOpq0W4"
      "cWBYGNQWLGW60QXeksVQEBGQzkfM+6+/"
      "I8CfBQIDAQABo2cwZTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/"
      "zAdBgNVHQ4EFgQUC7NoO6/"
      "ar+"
      "5wpXbZIffMRBYH0PgwEAYJKwYBBAGCNxUBBAMCAQAwEQYDVR0gBAowCDAGBgRVHSAAMA0GCS"
      "qGSIb3DQEBDAUAA4ICAQBIxzf//"
      "8FoV9eLQ2ZGOiZrL+"
      "j63mihj0fxPTSVetpVMfSV0jhfLLqPpY1RMWqJVWhsK0JkaoUkoFEDx93RcljtbB6M2JHF50"
      "kRnRl6N1ged0T7wgiYQsRN45uKDs9ARU8bgHBZjJOB6A/"
      "VyCaVqfcfdwa4yu+c++"
      "hm2uU54NLSYsOn1LYYmiebJlBKcpfVs1sqpP1fL37mYqMnZgz62RnMER0xqAFSCOZUDJljK+"
      "rYhNS0CBbvvkpbiFj0Bhag63pd4cdE1rsvVVYl8J4M5A8S28B/"
      "r1ZdxokOcalWEuS5nKhkHrVHlZKu0HDIk318WljxBfFKuGxyGKmuH1eZJnRm9R0P313w5zdb"
      "X7rwtO/kYwd+HzIYaalwWpL5eZxY1H6/cl1TRituo5lg1oWMZncWdq/"
      "ixRhb4l0INtZmNxdl8C7PoeW85o0NZbRWU12fyK9OblHPiL6S6jD7LOd1P0JgxHHnl59zx5/"
      "K0bhsI+pQKB0OQ8z1qRtA66aY5eUPxZIvpZbH1/o8GO4dG2ED/"
      "YbnJEEzvdjztmB88xyCA9Vgr9/"
      "0IKTkgQYiWsyFM31k+OS4v4AX1PshP2Ou54+"
      "3F0Tsci41yQvQgR3pcgMJQdnfCUjmzbeyHGAlGVLzPRJJ7Z2UIo5xKPjBB1Rz3TgItIWPFGy"
      "qAK9Aq7WHzrY5XHP5kBgigi9YIBKbm6PUb89nwF+ay9zwqbiPujH55M/"
      "PNdYoPO2MabH+"
      "Y2lzc3hcZGlkOng1MDk6MDpzaGEyNTY6SV9faXVMMjVvWEVWRmRUUF9hQkx4X2VUMVJQSGJD"
      "UV9FQ0JRZllacHQ5czo6ZWt1OjEuMy42LjEuNC4xLjMxMS43Ni41OS4xLjJkZmVlZHVDb250"
      "YWluZXJQbGF0LUFNRC1VVk1rc2lnbmluZ3RpbWXBGmVTyIChaXRpbWVzdGFtcFkUSTCCFEUG"
      "CSqGSIb3DQEHAqCCFDYwghQyAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFsBgsqhkiG9w0BCRAB"
      "BKCCAVsEggFXMIIBUwIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCZ95qVu/"
      "C6ZjToQzVd4gLCIX5jnJWPDK1mDQpOI9RbswIGZSiv2HUlGBMyMDIzMTExNDE5MjAzMi4yOT"
      "ZaMASAAgH0AhhEJDC7K1iE55nBZ4QqG5oJwLRlSzoSac6ggdGkgc4wgcsxCzAJBgNVBAYTAl"
      "VTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaW"
      "Nyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdG"
      "lvbnMxJzAlBgNVBAsTHm5TaGllbGQgVFNTIEVTTjpFMDAyLTA1RTAtRDk0NzElMCMGA1UEAx"
      "McTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDpkwggcgMIIFCKADAgECAhMzAAAB2Z"
      "xcBZKwg2s+"
      "AAEAAAHZMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n"
      "dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x"
      "JjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIzMDYwMTE4MzI1"
      "OFoXDTI0MDIwMTE4MzI1OFowgcsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u"
      "MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAj"
      "BgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJzAlBgNVBAsTHm5TaGllbGQg"
      "VFNTIEVTTjpFMDAyLTA1RTAtRDk0NzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg"
      "U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANXpIM3WuBjbfTnIt0J1"
      "Q28cIQThnS5wPoIq8vmUDsczzVIyRbfpFTvtRoEv09Jy+"
      "Kp9XMTavalFtEy0MEzATHWJqLNXYRmw0Ya7N5Hdc1g5tC8lUtoKIGS0Bl2rvkE0UiKX5J92l"
      "eArNVBmIMEkM3nRYIAM2utvjxnhnv8q/"
      "LNoPgZv5pl4KKgHYaDWbnd37qlRMFzdY7nEdmL+"
      "usj9d2eGITr9uymOlTlq58KUgPHRAOrVBHDThp2sqFwNbIYvdJoGn+GM37gklTsrO+"
      "wpZlV1O5c+iOdpPBZwd0QZ/PGJoXfTN3xJjhhFRwwY85A5EfUg/"
      "CTDCWpCRzQcGQkJDOJpdj8imAxHD9c/hS/"
      "4kEnxFkYpk3XNE9ZP13m8cZRKZfebvtEqgJ+"
      "SBImJ8iJCLoVzQ5gpLqBk4Dud3i36WICuv2eKp4L9Rw065WtxULgJuTB8nZ4eRpaHXyxS3dQ"
      "PxAdgtDCf3k/"
      "4ebw9kmKCvVJEtyybyk4957s8Fud0j9V4omyZB2N6TZoU71UadS3MMMGjCWFeyGzBkwyQsn/"
      "iNTNCZQF+"
      "b4kAfXnXoT4bTbBLs2DMzCakdYKYBoV13sPIkioZrptxmtHtAAt2TAiFVAODNkC43GrC+"
      "HghrhkjlWjKPhvvNYCGa6unCkymKPP6J55bB/pl2bKxGNH/"
      "JnpReYZrAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUHDrBKVNnqAVeXTnD+zcZrV/"
      "nXCcwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZ"
      "OaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1"
      "TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZ"
      "QaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1"
      "lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/"
      "BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZIhvcN"
      "AQELBQADggIBACo21Vgs7rVMy4hqcLtyW3SL5dFFsfCfA2jTlDezimkW13icKYH9Mk8Mnq68"
      "SvLGzS/Dlj6NDBSIqeGXZUYbAirSlYMi5pbimkxXWlhB8np20EaRGJM/"
      "V4pW8BFhkxFohN71mHAkmdg/zekzEcLFoSxkLiKVjf/"
      "nl2p3hldMLP9ykblqeYNqu2daaDKzKA2y1PBtYklGPzmBhGSPGL+fEoCIQXGXoZ+"
      "RyddXLwNEVCPV3cCKqx4+h4jPG7WK4AlHAOt97g2coeqhOBay/t4JYmdaNZZG3tFEaum/"
      "MtCj8HFRvyLj1TBGD0blvGl3lK7Vvbbga/"
      "obUdFT6okcHXOh7jUPav+JzYE+"
      "i6xX2d5grmojk8cuyECfphNCWVtX2kJs5S9k7R213CnkcfZ/"
      "Dqh8k3Apw8SVqqQRzG+uGFFarA2BoRVPIhXiMxzyM9vHY2H3MDO2dv01+cMU4T7+"
      "AXxxmpNr9PrlMY0/e4yI/"
      "eCvychdDYhHAxVSguYa7ap+aEOh7Czd1y+"
      "TqzVoDqZcfD4wA0QgMoqPDeLYbom1mQR6a7U5e2ySD+0ad/"
      "LBoyCrkJq5T1vp6dO0D5QT4YqeaJBbphQc+EEjQvZAbvpNEGt7k+k1UeLJz/"
      "TVuNQQyl5oH4icAficPFhfHXzBskT578hsy/"
      "TXjsQUvv3Z0QsXRfCqpxTRMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBg"
      "kqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBg"
      "NVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAx"
      "MpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMT"
      "gyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3"
      "RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS"
      "YwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQ"
      "EBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/"
      "e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/"
      "1xPx2b3lVNxWuJ+Slr+"
      "uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/"
      "YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/"
      "W7IVWTe/"
      "dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik"
      "3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/"
      "SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc"
      "6ZNN3SUHDSCD/"
      "AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKH"
      "YC4jMYctenIPDC+"
      "hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJ"
      "bqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/"
      "eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQID"
      "AQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/"
      "y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEA"
      "YI3TIN9AQEwQTA/"
      "BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9z"
      "aXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIA"
      "QwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/"
      "MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0"
      "dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8y"
      "MDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu"
      "bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0G"
      "CSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/"
      "qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+"
      "2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3"
      "m2CDPVtI1TkeFN1JFe53Z/"
      "zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/"
      "AyeixmJ5/"
      "ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+"
      "ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU"
      "BHG/"
      "ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3"
      "rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/"
      "g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/"
      "wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+"
      "7X6gMTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8jGC"
      "BA0wggQJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYD"
      "VQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT"
      "HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB2ZxcBZKwg2s+"
      "AAEAAAHZMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw"
      "LwYJKoZIhvcNAQkEMSIEIICTLnVJTYHff0RhE3uZmq3HiBHv1TC5tEA1r+"
      "18D6H1MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgn6AVsi06b9QwMCcRPNsl7S7QNZ"
      "3YyCmBvRJxtCAHefMwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3"
      "RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS"
      "YwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAdmcXAWSsINrPg"
      "ABAAAB2TAiBCASe0UZ9esPNmm71kbeDGRWh76rH0q9SniHO5k8rIvMvTANBgkqhkiG9w0BAQ"
      "sFAASCAgDU9AD4W0lH5cGWYVuke9VDUZXu8ne+kLoEBYl0Hze83ewUPH/"
      "esUtWfpns240158Jimu9WkNnVzFzARta/b8whyosuLTQYGJtreeOfQzpModQz/"
      "Yfj94LZwn2YA1OoM8xEQQ1RY5CYL9nEKT8y9SZ3k8EAnmVhhtusQYv8A+"
      "NtEAWZA0NXVRSMeXx7S+e1xBwqFvDNT4JmXrwHujTj+/"
      "zf97etxd1wFD3QcHFAHBNjrAugQ6t2daeRQof1IIzP0G78m+XGLiFR/"
      "gjgzrzk1MkmlyxdXTkDFKnQu3ObED6aR8BAx2hn8Qu2+i/"
      "i56ZBNRi1hFVujL3E0+je0ggpcLwxvQzEQMdjuykydWqhgJLKYzLOOA/"
      "CaA0l3jjrRKT1GstCnyT/"
      "RpEPjQZpuL+HMQt0TW87IwwfXucGPtVi8FkH8Ncx7U3mpbp3n8Z7ssu8Hv2y/"
      "uNXgO7ngv3+GhNHC8zRPdAPnBqNAbgqqDSK6A9OS5Xqbr/P8XjTHiE9V1h/"
      "9Vw7zUtMXlQhMuepHwXefFvUeM5lSgmyfF/"
      "k9uOUNRRWPBxfuE0xV4ChnT1KzKLd7a2H+J+KjKH+"
      "Rh6VX7tv3ahRJXz5UTqNhx02ik1tXnvPLAgItvvythb9IGPx/"
      "Q7G8aBDmj4cL6J+"
      "qkiSw4WAUDZHHHZcpaXw3bUifF9fIkdlmFiuewogICJ4LW1zLXNldnNucHZtLWd1ZXN0c3Zu"
      "IjogIjEwMCIsCiAgIngtbXMtc2V2c25wdm0tbGF1bmNobWVhc3VyZW1lbnQiOiAiMDJjM2Iw"
      "ZDViZjFkMjU2ZmE0ZTNiNWRlZWZjMDdiNTVmZjJmNzAyOTA4NWVkMzUwZjYwOTU5MTQwYTFh"
      "NTFmMTMxMDc1M2JhNWFiMmMwM2EwNTM2YjFjMGMxOTNhZjQ3Igp9WQGAuqzoQ90fHQw503pi"
      "ez4xHKc7AxT8ezEbw/jV2ka6DlhBU/"
      "LaEYoTDfzukhjvAfuFY8g5O4GKzb0HtvYXOjZDC8fpBQ/"
      "RAsM3xFGZnwq8tKU0NJo3qSbGp7EOY5dgLJfkA+nv8Eu5Zgdfb+"
      "Jq3RF2dRxhLezKFAMpWci5ZGb04a9waBh2M8dvlRNME0q/"
      "2z11Wkuy2rtRw0EKQs725V1JcQD+Jv6cv/"
      "nD4shoCz6+Q7E71zWFMRtr7uuY7DD4LGT0HIYnEmmqCO/"
      "Gq6LpPuqptGZG7iivk1GEP1JaEXd/"
      "JXx81PoZdYjHG+5ho8vlGbbE8doNj6Jl5uNX+YFb4+"
      "JHtbxmGyNp9fEhM5IzuXlG8SI0ElNTdBweMKL87LWeTdygcM5zsFULCHlNCNf5NNDjP0kZoO"
      "0BYulfE74Ba/"
      "71qZQEnmKhdWDim4sdVl8t7UIu4AbtMpqBEjea6leuXnckZytZVDGY6C6+"
      "4DnIlfB7jEHE4f11xqAnRcxKvSpSf6Vj",
      // Endorsed TCB
      "0300000000000873"};
}

}  // namespace google::scp::azure::attestation
