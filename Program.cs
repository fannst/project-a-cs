using System;
using ProjectA;

namespace driver
{
    class Program
    {
        static void Main(string[] args)
        {
            DiscoveryDriver discoveryDriver = new DiscoveryDriver (8084, 1000, 5, DiscoveryPacketDeviceID.ProjectA);
            discoveryDriver.Start ();
            while (!discoveryDriver.GetDone ());
            
            foreach (DiscoveryDriverDevice device in discoveryDriver.GetDiscoveryDevices ()) {
                Console.WriteLine (device.ToDeviceString ());
            }

            DiscoveryDriverDevice d = discoveryDriver.GetDiscoveryDevices ()[0];
            ControlDriver control = new ControlDriver ();
            control.Start (d.GetIPAddress (), d.GetPort ());

            control.EnableDisableStepper (0, true);
            control.MoveStepper (0, -13000);
            
            for (;;);
        }
    }
}
