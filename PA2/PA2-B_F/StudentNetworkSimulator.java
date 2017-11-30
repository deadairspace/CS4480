import java.util.ArrayList;
public class StudentNetworkSimulator extends NetworkSimulator
{
    /*
     * Predefined Constants (static member variables):
     *
     *   int MAXDATASIZE : the maximum size of the Message data and
     *                     Packet payload
     *
     *   int A           : a predefined integer that represents entity A
     *   int B           : a predefined integer that represents entity B
     *
     *
     * Predefined Member Methods:
     *
     *  void stopTimer(int entity):
     *       Stops the timer running at "entity" [A or B]
     *  void startTimer(int entity, double increment):
     *       Starts a timer running at "entity" [A or B], which will expire in
     *       "increment" time units, causing the interrupt handler to be
     *       called.  You should only call this with A.
     *  void toLayer3(int callingEntity, Packet p)
     *       Puts the packet "p" into the network from "callingEntity" [A or B]
     *  void toLayer5(int entity, String dataSent)
     *       Passes "dataSent" up to layer 5 from "entity" [A or B]
     *  double getTime()
     *       Returns the current time in the simulator.  Might be useful for
     *       debugging.
     *  void printEventList()
     *       Prints the current event list to stdout.  Might be useful for
     *       debugging, but probably not.
     *
     *
     *  Predefined Classes:
     *
     *  Message: Used to encapsulate a message coming from layer 5
     *    Constructor:
     *      Message(String inputData):
     *          creates a new Message containing "inputData"
     *    Methods:
     *      boolean setData(String inputData):
     *          sets an existing Message's data to "inputData"
     *          returns true on success, false otherwise
     *      String getData():
     *          returns the data contained in the message
     *  Packet: Used to encapsulate a packet
     *    Constructors:
     *      Packet (Packet p):
     *          creates a new Packet that is a copy of "p"
     *      Packet (int seq, int ack, int check, String newPayload)
     *          creates a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and a
     *          payload of "newPayload"
     *      Packet (int seq, int ack, int check)
     *          chreate a new Packet with a sequence field of "seq", an
     *          ack field of "ack", a checksum field of "check", and
     *          an empty payload
     *    Methods:
     *      boolean setSeqnum(int n)
     *          sets the Packet's sequence field to "n"
     *          returns true on success, false otherwise
     *      boolean setAcknum(int n)
     *          sets the Packet's ack field to "n"
     *          returns true on success, false otherwise
     *      boolean setChecksum(int n)
     *          sets the Packet's checksum to "n"
     *          returns true on success, false otherwise
     *      boolean setPayload(String newPayload)
     *          sets the Packet's payload to "newPayload"
     *          returns true on success, false otherwise
     *      int getSeqnum()
     *          returns the contents of the Packet's sequence field
     *      int getAcknum()
     *          returns the contents of the Packet's ack field
     *      int getChecksum()
     *          returns the checksum of the Packet
     *      int getPayload()
     *          returns the Packet's payload
     *
     */

    // Add any necessary class variables here.  Remember, you cannot use
    // these variables to send messages error free!  They can only hold
    // state information for A or B.
    // Also add any necessary methods (e.g. checksum of a String)

    // Go-Back-N variables
    private int base;
    private int n_Sequence_No;
    private int frameSize;
    private ArrayList<Packet> buff;
    private int buffMaximum;

    //interchanging variable
    private int sequenceno;
	private int sequencenoexpected;
	Packet acurrpacket;
	Packet packetbcurrent;
	boolean ismessagemoving;

    int totalpacketssent = 0;
	int totalpacketsresent = 0;
	int totalackpacketssent = 0;
	int totalcorruptpacketsreceived = 0;
	double rttstarted = 0.0;
	double totalrtttime = 0.0;
	int totalrtts = 0;
    // This is the constructor.  Don't touch!
    public StudentNetworkSimulator(int numMessages,
                                   double loss,
                                   double corrupt,
                                   double avgDelay,
                                   int trace,
                                   long seed)
    {
        super(numMessages, loss, corrupt, avgDelay, trace, seed);
    }
    // Providing all Stat
    @Override
    public void runSimulator() {
        super.runSimulator();
        System.out.println("\n");
        System.out.println("Packet Transmission Info");
        System.out.println("\n");

        System.out.println("Total Packets Sent:\t" + totalpacketssent);
        System.out.println("Total Packets Resent:\t\t" + totalpacketsresent);
        System.out.println("Total ACK Packets Sent:\t\t\t\t" + totalackpacketssent);
        System.out.println("Total Corrupt Packets Received:\t\t" + totalcorruptpacketsreceived);
        System.out.println("Total of packets lost:\t\t\t\t" + nLost);

        if (totalrtts > 0)
            System.out.println("RTT Avg:\t\t\t\t\t" + (totalrtttime / totalrtts) + "\n");
        else
            System.out.println("RTT Avg:\t\t\t\t\t0\n");
    };

    // This routine will be called whenever the upper layer at the sender [A]
    // has a message to send.  It is the job of your protocol to insure that
    // the data in such a message is delivered in-order, and correctly, to
    // the receiving upper layer.

    // Go-Back-N version
    protected void aOutput(Message message) {
        if (buff.size() < base + frameSize + buffMaximum) {
            System.out.println("A: Message received through layer 5. (" + message.getData() + ")");
            buff.add(makePacket(message, A, B, buff.size(), buff.size()));
            sendNextPackets();
            totalpacketssent++;
        } else {
            System.out.println("A: frame and buff is full. Leaving message.");
        }
    }

    // Go-Back-N version
    protected void aInput(Packet packet)
    {
        System.out.println("A: Packet received from B through layer 3.");

        totalrtttime += getTime() - rttstarted;
        totalrtts++;

        if (isCorruptPacket(packet)) {
            System.out.println("A: Packet sent by B is corrupt. Timeout.");
            totalcorruptpacketsreceived++;

       } else {

            System.out.println("A: Packet "+packet.getAcknum()+" acknowledged from side B.");
            base = packet.getAcknum() + 1;
            if (base == n_Sequence_No)
            stopTimer(A);
        }

    }

    // This routine will be called when A's timer expires (thus generating a
    // timer interrupt). You'll probably want to use this routine to control
    // the retransmission of packets. See startTimer() and stopTimer(), above,
    // for how the timer is started and stopped.

    // Go-Back-N version
    protected void aTimerInterrupt()
    {
        System.out.println("A: The timer was interrupted, resending the message.");
        rttstarted = getTime();
        startTimer();
        for (int i = base; i < n_Sequence_No; i++) {
         System.out.println("A: Retransmitting unacknowledged packet " + i + ".");
         toLayer3(A, buff.get(i));
         totalpacketsresent++;
        }
    }

    // This routine will be called once, before any of your other A-side
    // routines are called. It can be used to do any required
    // initialization (e.g. of member variables you add to control the state
    // of entity A).

    // Go-Back-N version
    protected void aInit()
    {
        System.out.println("A: Setting sequence number to 0.");
        base = 0;

        System.out.println("A: Setting next sequence number to 0.");
        n_Sequence_No = 0;

        System.out.println("A: Setting Frame Size to 8.");
        frameSize = 8;

        System.out.println("A: Setting message buffer Size to 50.");
        buffMaximum = 50;
        buff = new ArrayList<>();

    }

    // This routine will be called whenever a packet sent from the B-side
    // (i.e. as a result of a toLayer3() being done by an A-side procedure)
    // arrives at the B-side.  "packet" is the (possibly corrupted) packet
    // sent from the A-side.

    // Go-Back-N version
    protected void bInput(Packet packet)
    {
        System.out.println("B: Package from A was received through layer 3 ("+packet.getPayload()+").");

        if (isCorruptPacket(packet) || packet.getSeqnum() != sequencenoexpected) {
            System.out.println("B: Packet received from A is corrupt or repeated. Resending the ACK.");
            if (isCorruptPacket(packet))
                totalcorruptpacketsreceived++;

        } else {
            System.out.println("B: Packet received from A checks out. Switching to layer 5 and sending the ACK.");
            toLayer5(B, packet.getPayload());
            //sequencenoexpected = packet.getSeqnum() == 0 ? 1 : 0;
            packetbcurrent = makePacket(new Message(" "), B, A, 0, packet.getSeqnum());
        }

        toLayer3(B, packetbcurrent);
        totalackpacketssent++;
    }

    // This routine will be called once, before any of your other B-side
    // routines are called. It can be used to do any required
    // initialization (e.g. of member variables you add to control the state
    // of entity B).
    protected void bInit()
    {
        System.out.println("B: Setting expected sequence number to 0.");
        sequencenoexpected = 0;

        packetbcurrent = makePacket(new Message(" "), B, A, 0, -1);
    }

    /*
     * METHODS
     */
    private Packet makePacket(Message message, int sender, int receiver, int seqno, int acknum) {

        String container = message.getData();
        int checksum = newchksm(seqno, acknum, container);

        return new Packet(seqno, acknum, checksum, container);
    }

    private String changesidestr(int side) {
        return side == A ? "A" : "B";
    }

    private int newchksm(int seqno, int acknum, String container) {
        int checksum = 0;

        checksum += seqno;
        checksum += acknum;

        for (char c : container.toCharArray())
            checksum += (int) c;

        return checksum;
    }
    private void sendNextPackets() {
        try {
            while (n_Sequence_No < base + frameSize) {
                if (n_Sequence_No < buff.size())
                    System.out.println("A: Sending packet "+ n_Sequence_No +" to side B.");

                toLayer3(A, buff.get(n_Sequence_No));

                if (base == n_Sequence_No)
                    startTimer();

                n_Sequence_No++;
            }
        } catch (IndexOutOfBoundsException e) {
            System.out.println("A: Frame and buff are empty. We don't have more packet to send.");
        }
    }

    private boolean isCorruptPacket(Packet packet) {
        int calculatedChecksum = 0;
        calculatedChecksum += packet.getSeqnum();
        calculatedChecksum += packet.getAcknum();

        for (char c : packet.getPayload().toCharArray())
            calculatedChecksum += (int) c;

        return calculatedChecksum != packet.getChecksum();
    }

    private void startTimer() {
        //messaging for 1000
        startTimer(A, 140.0);
    }

}
