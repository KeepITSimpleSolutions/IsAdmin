using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace MarshallingExample
{


    class Program
    {

        protected struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        protected struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        protected struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        //This enum was huge, I cut it down to save space
        protected enum TOKEN_INFORMATION_CLASS
        {
            /// <summary>
            /// The buffer receives a TOKEN_PRIVILEGES structure that contains the privileges of the token.
            /// </summary>
            TokenPrivileges = 3
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        protected static extern bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, ref int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName);

        static void Main(string[] args)
        {
            Console.BackgroundColor = ConsoleColor.Blue;
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine("INFRABEL CHECK ADMIN");
            Console.ResetColor();

            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            Console.Write("IsAdmin = ");
            
            if (principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));
                Console.WriteLine();
                Console.ResetColor();
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write(principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator));
                Console.WriteLine();
                Console.ResetColor();
            }

            //Check and print the privileges this token has
            CheckPrivileges(WindowsIdentity.GetCurrent().Token);

            Thread.Sleep(2000);

            //Console.ReadKey();
        }

        public bool IsCurrentProcessAdmin()
        {
            var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            var principal = new System.Security.Principal.WindowsPrincipal(identity);
            return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }

        //test function to output privileges for an account
        private static bool CheckPrivileges(IntPtr thisHandle)
        {
            int iTokenInfLength = 0; //holds the length of the TOKEN_PRIVILEGES structure that will be returned by GetTokenInformation

            //First call to GetTokenInformation returns the length of the structure that will be returned on the next call
            GetTokenInformation(thisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, iTokenInfLength, ref iTokenInfLength);

            //Allocate a block of memory large enough to hold the expected structure
            IntPtr ipTokenInformation = Marshal.AllocHGlobal(iTokenInfLength);
            //ipTokenInformation holds the starting location readable as an integer
            //you can view the memory location using Ctrl-Alt-M,1 or Debug->Windows->Memory->Memory1 in Visual Studio
            //and pasting the value of ipTokenInformation into the search box (it's still empty right now though)
            if (GetTokenInformation(thisHandle, TOKEN_INFORMATION_CLASS.TokenPrivileges, ipTokenInformation, iTokenInfLength, ref iTokenInfLength))
            {
                //If GetTokenInformation doesn't return false then the structure should be sitting in the space reserved by ipTokenInformation
                //at this point

                //What was returned is a structure of type TOKEN_PRIVILEGES which has two values, a UInt32 followed by an array
                //of LUID_AND_ATTRIBUTES structures. Because we know what to expect and we know the order to expect it we can section
                //off the memory into marshalled structures and do some math to figure out where to start our next marshal

                uint uiPrivilegeCount = (uint)Marshal.PtrToStructure(ipTokenInformation, typeof(uint)); //Get the count

                //lets create the structure we should have had in the first place
                LUID_AND_ATTRIBUTES[] aLuidAa = new LUID_AND_ATTRIBUTES[uiPrivilegeCount]; //initialize an array to the right size
                LUID_AND_ATTRIBUTES cLuidAa = new LUID_AND_ATTRIBUTES();

                //ipPointer will hold our new location to read from by taking the last pointer plus the size of the last structure read
                IntPtr ipPointer = new IntPtr(ipTokenInformation.ToInt32() + sizeof(uint)); //first laa pointer
                cLuidAa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(ipPointer, typeof(LUID_AND_ATTRIBUTES)); //Read the memory location
                aLuidAa[0] = cLuidAa; //Add it to the array

                //After getting our first structure we can loop through the rest since they will all be the same
                for (int i = 1; i < uiPrivilegeCount; ++i)
                {
                    ipPointer = new IntPtr(ipPointer.ToInt32() + Marshal.SizeOf(cLuidAa)); //Update the starting point in ipPointer
                    cLuidAa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(ipPointer, typeof(LUID_AND_ATTRIBUTES)); //Read the memory location
                    aLuidAa[i] = cLuidAa; //Add it to the array
                }//next

                TOKEN_PRIVILEGES cPrivilegeSet = new TOKEN_PRIVILEGES();
                cPrivilegeSet.PrivilegeCount = uiPrivilegeCount;
                cPrivilegeSet.Privileges = aLuidAa;
                //now we have what we should have had to begin with
                Console.WriteLine("Privilege Count: {0}", cPrivilegeSet.PrivilegeCount.ToString());


                //This loops through the LUID_AND_ATTRIBUTES array and resolves the LUID names with a
                //call to LookupPrivilegeName which requires us to first convert our managed structure into an unmanaged one
                //so we get to see what it looks like to do it backwards
                foreach (LUID_AND_ATTRIBUTES cLaa in cPrivilegeSet.Privileges)
                {
                    System.Text.StringBuilder sb = new System.Text.StringBuilder();
                    int iLuidNameLen = 0; //Holds the length of structure we will be receiving LookupPrivilagename
                    IntPtr ipLuid = Marshal.AllocHGlobal(Marshal.SizeOf(cLaa.Luid)); //Allocate a block of memory large enough to hold the structure
                    Marshal.StructureToPtr(cLaa.Luid, ipLuid, true); //Write the structure into the reserved space in unmanaged memory
                    LookupPrivilegeName(null, ipLuid, null, ref iLuidNameLen); // call once to get the name length we will be receiving
                    sb.EnsureCapacity(iLuidNameLen + 1); //Make sure there is enough room for it
                    if (LookupPrivilegeName(null, ipLuid, sb, ref iLuidNameLen))
                    { // call again to get the name
                        Console.WriteLine("[{0}] : {1}", cLaa.Attributes.ToString(), sb.ToString());
                    }//end if
                    Marshal.FreeHGlobal(ipLuid); //Free up the reserved space in unmanaged memory (Should be done any time AllocHGlobal is used)
                }//next
                Marshal.FreeHGlobal(ipTokenInformation);  //Free up the reserved space in unmanaged memory (Should be done any time AllocHGlobal is used)
            }//end if GetTokenInformation
            return true;
        }//CheckPrivileges
    }//Program
}//MarshallingExample
