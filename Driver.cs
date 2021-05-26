/*
    Copyright 2021 Luke A.C.A. Rieff

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ProjectA
{
    /////////////////////////////////////////////////////////////////////////
    // Control
    /////////////////////////////////////////////////////////////////////////

    public enum ControlPktOp
    {
        ConnectionRequest = 0,
        ConnectionRequestApproved = 1,
        ConnectionRequestRejected = 2,
        StepperInfoRequest = 4,
        StepperMoveTo = 5,
        StepperEnableDisable = 6,
        StepperInfoResponse = 7
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ControlPkt
    {
        public ushort   totalLength;
        public ushort   opCode;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ControlPkt_StepperInfo
    {
        public byte     motor;
        public byte     flags;
        public int      targetPosition;
        public int      currentPosition;
        public ushort   minimumSpeed;
        public ushort   currentSpeed;
        public ushort   targetSpeed;
        public byte     hasNext;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ControlPkt_StepperMoveTo
    {
        public byte     motor;
        public uint     position;
        public byte     hasNext;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ControlPkt_StepperEnaDisa
    {
        public byte     motor;
        public byte     enabled;
        public byte     hasNext;
    }

    public class StepperInfo {
        public readonly byte motor;
        public readonly byte flags;
        public readonly int targetPos;
        public readonly int currentPos;
        public readonly int minimumSpeed;
        public readonly int currentSpeed;
        public readonly int targetSpeed;

        /// Creates new stepper info instance.
        public StepperInfo (byte motor, byte flags, int targetPos, int currentPos, int minSpeed, int currSpeed, int targetSpeed) {
            this.motor = motor;
            this.flags = flags;
            this.targetPos = targetPos;
            this.currentPos = currentPos;
            this.minimumSpeed = minSpeed;
            this.currentSpeed = currSpeed;
            this.targetSpeed = targetSpeed;
        }
    }

    public class ControlDriver
    {
        private TcpClient m_TCPClient;

        public enum ErrorCode
        {
            SocketConnectionFailure,
            ConnectionRejected,
            InvalidOpcode,
            SocketReadFailure,
            SocketWriteFailure,
            FormatError,
            OK
        }

        /// Creates new ControlDriver instance.
        public ControlDriver()
        {
            m_TCPClient = null;
        }

        /// Starts the driver.
        public ErrorCode Start(IPAddress iPAddress, ushort port)
        {
            ErrorCode error;

            // Creates and connects the TCP client.
            m_TCPClient = new TcpClient();

            try
            {
                m_TCPClient.Connect(iPAddress, port);
            }
            catch (SocketException e)
            {
                Console.WriteLine("Failed to connect: " + e.ToString());
                return ErrorCode.SocketConnectionFailure;
            }

            // Sends the connectionr request and awaits the response.
            if ((error = SendConnectionRequest()) != ErrorCode.OK)
                return error;
            if ((error = AwaitConnectionResponse()) != ErrorCode.OK)
                return error;

            // Returns OK.
            return ErrorCode.OK;
        }

        /// Reads N bytes from the socket.
        private byte[] ReadNBytes(int n)
        {
            byte[] res = new byte[n];
            int i = 0;

            // Stays in loop until we've read the N bytes we want.
            while (i < n)
            {
                int read;
                if ((read = m_TCPClient.GetStream().Read(res, i, n - i)) == -1)
                    return null;

                i += read;
            }

            return res;
        }

        /// Moves the specified stepper to specified position.
        public ErrorCode MoveStepper(byte stepper, int pos)
        {
            ErrorCode error;
            ControlPkt_StepperMoveTo moveTo = new ControlPkt_StepperMoveTo
            {
                motor = stepper,
                position = (uint)pos,
                hasNext = 0
            };

            // Sends the packet head and the move body.
            if ((error = SendControlPacketHead(ControlPktOp.StepperMoveTo, Marshal.SizeOf(moveTo))) != ErrorCode.OK)
                return error;
            else if ((error = WriteBinary(moveTo)) != ErrorCode.OK)
                return error;

            // Return OK.
            return ErrorCode.OK;
        }

        /// Enables or Disables the specified stepper.
        public ErrorCode EnableDisableStepper(byte stepper, bool ena)
        {
            ErrorCode error;
            ControlPkt_StepperEnaDisa enadisa = new ControlPkt_StepperEnaDisa
            {
                motor = stepper,
                enabled = ena ? (byte)1 : (byte)0,
                hasNext = 0
            };

            // Writes the packet head and the enadisa body.
            if ((error = SendControlPacketHead(ControlPktOp.StepperEnableDisable, Marshal.SizeOf(enadisa))) != ErrorCode.OK)
                return error;
            else if ((error = WriteBinary(enadisa)) != ErrorCode.OK)
                return error;

            // Return OK.
            return ErrorCode.OK;
        }


        /// Requests the stepper information.
        public ErrorCode GetStepperInfo (ref List<StepperInfo> target) {
            BinaryReader binaryReader;
            byte[] bytes = null;

            // Sends the data request.
            ErrorCode error;
            if ((error = SendControlPacketHead (ControlPktOp.StepperInfoRequest, 0)) != ErrorCode.OK)
                return error;

            // First reads the packet head, so we can check the total
            //  length required, and read that.
            bytes = ReadNBytes (4);
            if (bytes == null)
                return ErrorCode.SocketReadFailure;

            // Parses the read header into structure.
            ControlPkt controlPkt;
            try {
                binaryReader = new BinaryReader (new MemoryStream(bytes));
                controlPkt = new ControlPkt {
                    totalLength = binaryReader.ReadUInt16 (),
                    opCode = binaryReader.ReadUInt16 ()
                };
            } catch (Exception e) {
                Console.WriteLine ("Failed to parse status header: " + e.ToString ());
                return ErrorCode.FormatError;
            }

            // Reads the N bytes specified by the control head.
            bytes = ReadNBytes (controlPkt.totalLength);
            if (bytes == null)
                return ErrorCode.SocketReadFailure;

            // Parses the read stepper info.
            try {
                binaryReader = new BinaryReader (new MemoryStream (bytes));
                bool next = false;
                do {
                    ControlPkt_StepperInfo stepperInfo = new ControlPkt_StepperInfo {
                        motor = binaryReader.ReadByte (),
                        flags = binaryReader.ReadByte (),
                        targetPosition = binaryReader.ReadInt32 (),
                        currentPosition = binaryReader.ReadInt32 (),
                        minimumSpeed = binaryReader.ReadUInt16 (),
                        currentSpeed = binaryReader.ReadUInt16 (),
                        targetSpeed = binaryReader.ReadUInt16 (),
                        hasNext = binaryReader.ReadByte()
                    };

                    target.Add (new StepperInfo (stepperInfo.motor, stepperInfo.flags, stepperInfo.targetPosition,
                        stepperInfo.currentPosition, stepperInfo.minimumSpeed, stepperInfo.currentSpeed, stepperInfo.targetSpeed));

                    next = stepperInfo.hasNext == (byte) 1 ? true : false;
                } while (next);
            } catch (Exception e) {
                Console.WriteLine ("Failed to parse stepper info: " + e.ToString ());
                return ErrorCode.FormatError;
            }

            return ErrorCode.OK;
        }

        /// Awaits the response to  the connection request.
        private ErrorCode AwaitConnectionResponse()
        {
            // Reads 4 bytes.
            byte[] data = ReadNBytes(4);
            if (data == null)
                return ErrorCode.SocketReadFailure;

            // Reads the response.
            BinaryReader reader = new BinaryReader(new MemoryStream(data));
            ControlPkt pkt = new ControlPkt
            {
                totalLength = reader.ReadUInt16(),
                opCode = reader.ReadUInt16()
            };

            // Checks if we're accepted or not.
            switch ((ControlPktOp)pkt.opCode)
            {
                case ControlPktOp.ConnectionRequestApproved:
                    return ErrorCode.OK;
                case ControlPktOp.ConnectionRequestRejected:
                    Close();
                    return ErrorCode.ConnectionRejected;
                default:
                    return ErrorCode.InvalidOpcode;
            }
        }

        /// Closes the control driver.
        private void Close()
        {
            m_TCPClient.Close();
            m_TCPClient = null;
        }

        /// Sends the connection request.
        private ErrorCode SendConnectionRequest()
        {
            return SendControlPacketHead(ControlPktOp.ConnectionRequest, 0);
        }

        /// Writes an object in binary to the socket.
        private ErrorCode WriteBinary(object packet)
        {
            // Allocates the binary buffer.
            int size = Marshal.SizeOf(packet);
            byte[] bytes = new byte[size];

            // Turns the packet struct into binary array.
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(packet, ptr, true);
            Marshal.Copy(ptr, bytes, 0, size);
            Marshal.FreeHGlobal(ptr);

            // Sends the binary data.
            try
            {
                m_TCPClient.GetStream().Write(bytes, 0, size);
            }
            catch (IOException e)
            {
                Console.WriteLine("Socket write failure: " + e.ToString());
                return ErrorCode.SocketWriteFailure;
            }

            // Returns OK.
            return ErrorCode.OK;
        }

        /// Sends an control packet head to the socket.
        private ErrorCode SendControlPacketHead(ControlPktOp op, int length)
        {
            return WriteBinary(new ControlPkt
            {
                totalLength = ((ushort)(length + 4)),
                opCode = (ushort)op
            });
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // Discovery
    /////////////////////////////////////////////////////////////////////////

    public abstract class DiscoveryPacketFlags
    {
        public static readonly byte Request = (1 << 0);
        public static readonly byte Response = (1 << 1);
    }

    public enum DiscoveryPacketDeviceID : ushort
    {
        ProjectA = 0x7132
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DiscoveryPacketRequest
    {
        public ushort devID;
        public byte flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct DiscoveryPacketResponse
    {
        public ushort devID;
        public byte flags;
        public ushort port;
        public ushort nameLen;
        public byte[] name;
    }

    public class DiscoveryDriverDevice
    {
        private ushort m_Port;
        IPAddress m_IPAddress;
        private string m_Name;

        public DiscoveryDriverDevice(ushort port, IPAddress iPAddress, string name)
        {
            m_Port = port;
            m_IPAddress = iPAddress;
            m_Name = name;
        }

        public IPAddress GetIPAddress()
        {
            return m_IPAddress;
        }

        public ushort GetPort()
        {
            return m_Port;
        }

        public string GetName()
        {
            return m_Name;
        }

        public string ToDeviceString()
        {
            return m_IPAddress.ToString() + ":" + m_Port.ToString() + " (" + m_Name + ")";
        }
    }

    public class DiscoveryDriver
    {
        private ushort m_Port;
        private int m_ReceptionTimeout;
        private ushort m_PacketCount;
        private List<DiscoveryDriverDevice> m_DiscoveryDevices;
        private bool m_Done;
        private UdpClient m_UDPClient;
        private Task m_ReceptionTask;
        private DiscoveryPacketDeviceID m_DeviceID;

        /// Creates an new discovery driver instance.
        public DiscoveryDriver(ushort port, int receptionTimeout, ushort packetCount, DiscoveryPacketDeviceID deviceID)
        {
            m_Port = port;
            m_ReceptionTimeout = receptionTimeout;
            m_PacketCount = packetCount;
            m_DeviceID = deviceID;

            m_UDPClient = new UdpClient();
            m_UDPClient.Client.Bind(new IPEndPoint(IPAddress.Any, port));

            m_Done = true;
            m_DiscoveryDevices = null;
        }

        /// Gets an list of all the discovered devices.
        public List<DiscoveryDriverDevice> GetDiscoveryDevices()
        {
            return m_DiscoveryDevices;
        }

        /// The on packet callback.
        private void OnPacket(IAsyncResult res)
        {
            IPEndPoint from = new IPEndPoint(0, 0);
            byte[] message = m_UDPClient.EndReceive(res, ref from);

            // Attempts to parse the packet.
            try
            {
                DiscoveryPacketResponse response = new DiscoveryPacketResponse();

                // Reads the response packet.
                BinaryReader reader = new BinaryReader(new MemoryStream(message));
                response.devID = reader.ReadUInt16();
                response.flags = reader.ReadByte();
                response.port = reader.ReadUInt16();
                response.nameLen = reader.ReadUInt16();
                response.name = reader.ReadBytes(response.nameLen);

                // Makes sure the packet is an response, and contains the propper device id.
                if (response.devID != (ushort)m_DeviceID || (response.flags & DiscoveryPacketFlags.Response) == 0)
                    return;

                // Makes sure the packet is not part of it yet.
                foreach (DiscoveryDriverDevice item in m_DiscoveryDevices)
                {
                    if (item.GetIPAddress().Equals(from.Address))
                        return;
                }

                // Adds the new packet.
                m_DiscoveryDevices.Add(new DiscoveryDriverDevice(response.port, from.Address, Encoding.UTF8.GetString(response.name)));
            }
            catch (Exception) { }

            // Starts the new async receieve.
            m_UDPClient.BeginReceive(new AsyncCallback(OnPacket), null);
        }

        /// Starts the reception task, this will stop the discovery
        ///  after N seconds.
        private void StartReceptionTask()
        {
            m_DiscoveryDevices = new List<DiscoveryDriverDevice>();
            m_UDPClient.BeginReceive(new AsyncCallback(OnPacket), null);

            // Creates the reception task.
            m_ReceptionTask = new Task(() =>
            {
                System.Threading.Thread.Sleep(m_ReceptionTimeout);
                m_Done = true;
                m_ReceptionTask = null;
            });

            // Starts the reception task.
            m_ReceptionTask.Start();
        }

        public bool IsDone()
        {
            return m_Done;
        }

        /// triggers the start of the discovery.
        public void Start()
        {
            // Checks if we can actually claim the driver.
            if (!m_Done)
                throw new Exception("Ongoing discovery is already happening.");

            // Sets done to false.
            m_Done = false;

            // Sends the discovery packets.
            for (ushort i = 0; i < m_PacketCount; ++i)
                SendDiscoveryPacket();

            // Starts the reception task.
            StartReceptionTask();
        }

        /// Sends a single discovery packet.
        public void SendDiscoveryPacket()
        {
            // Creates the packet.
            DiscoveryPacketRequest request = new DiscoveryPacketRequest
            {
                devID = (ushort)DiscoveryPacketDeviceID.ProjectA,
                flags = DiscoveryPacketFlags.Request
            };

            // Allocates the binary buffer.
            int size = Marshal.SizeOf(request);
            byte[] bytes = new byte[size];

            // Turns the packet struct into binary array.
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(request, ptr, true);
            Marshal.Copy(ptr, bytes, 0, size);
            Marshal.FreeHGlobal(ptr);

            // Sends the broadcast packet.
            m_UDPClient.Send(bytes, size, new IPEndPoint(IPAddress.Broadcast, m_Port));
        }
    }
}
