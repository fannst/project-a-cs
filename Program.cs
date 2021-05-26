using System;
using ProjectA;

namespace driver
{
    class Program
    {
        static DiscoveryDriver s_DiscoveryDriver = new DiscoveryDriver (8084, 1000, 5, DiscoveryPacketDeviceID.ProjectA);
        static ControlDriver s_ControlDriver = new ControlDriver ();
        static DiscoveryDriverDevice s_TargetDevice = null;

        // Performs the device discovery.
        static void PerformDiscovery () {
            DiscoveryDriver.ErrorCode error;

            // Starts the discovery.
            if ((error = s_DiscoveryDriver.Start ()) != DiscoveryDriver.ErrorCode.OK) {
                Console.WriteLine ("Failed to start discovery: " + error.ToString ());
                return;
            }
            
            // Waits for the discovery to finish.
            while (!s_DiscoveryDriver.GetDone ());

            // Prints all the found devices.
            foreach (DiscoveryDriverDevice device in s_DiscoveryDriver.GetDiscoveryDevices ())
                Console.WriteLine ("Discovered device :: " + device.ToDeviceString ());

            // Attempts to get the device we are interested in.
            s_TargetDevice = s_DiscoveryDriver.GetDiscoveryDeviceByName ("Project-A DEMO");
        }

        static void Main(string[] args)
        {
            ControlDriver.ErrorCode controlDriverError;

            // Performs the discovery, and checks if the target device is found.
            PerformDiscovery ();
            if (s_TargetDevice == null) {
                Console.WriteLine ("Target device not found! shutting down.");
                return;
            }

            // Creates the control driver, and starts.
            if ((controlDriverError = s_ControlDriver.Start (s_TargetDevice.GetIPAddress (), s_TargetDevice.GetPort ())) != ControlDriver.ErrorCode.OK) {
                Console.WriteLine ("Failed to start control driver: " + controlDriverError.ToString ());
                s_ControlDriver.Close ();
                return;
            }

            // Performs some basic operations.
            s_ControlDriver.CheckError (s_ControlDriver.EnableDisableStepper (0, true));
            s_ControlDriver.CheckError (s_ControlDriver.MoveStepper (0, -13000));
            
            for (;;);
        }
    }
}
