package ass1;

import java.io.InterruptedIOException;
import java.net.*;
/**
 *	//WORKS:
 	//String askfor = "www.plan-international.gov"; //WORKS: SOA Record Support => no such dom
	//String askfor = "www.arc.gov.au";		//WORKS: +FIX_TEST+ arc.gov.au NS doe not reply, needs to try next ns (Works)
		//String askfor = "www.google.com";		//WORKS

 	//String askfor = "www.microsoft.com"; //OK WORKS but cnames start from root
		//TODO: Microsoft returns diffrent IP adresses depending on priority, A answer vs CNAME answer.
		 * If CNAME chain is followed recursivly regardless if server used iterative reply.??
		 or needs to GET to get HTML
	//String askfor = "www.db.de";  //OK WORKS but for CNAME it starts fresh

	//String askfor = "www.bbc.co.uk";	//WORKS: Needs to resolve NS IP => Create a getIP functino and call it on the stack
		//String askfor = "www.google.co.uk";  //WORKS but it bounces you to CNAME www.google.com: (Solve NS) Reply has NS but no ADD for ns

	String askfor = "www.amd.com";		//WORKS: But does not load page or needs to GET to get HTML

	//String askfor = "cycle.deric.net"; //TODO: Test if CNAME is pointing to previous CNAME. Circular CNAME Refs (Likley not tested)

		//String askfor = "www.smh.com.au";  //WORKS: Produces wrong IP ?!? -> test with dig to reproduce results
		//String askfor = "www.halo.com";    //Does not reply correct IP, possibly try other NS in list or needs to GET to get HTML

	//String askfor = "www.zmail.com";		//WORKS: FIXED: rrName len is var
        //String askfor = "www.zmail.unsw.edu.au";		//WORKS:
 */




/**
 * This is the main resolve class. It takes the first argument and passes it into a recursive domain resolve function.
 */
public class DNS_resolver {
	private static final String NO_IP_FOUND = "";				//Value for returning no ip.
	private static final int DEFAULT_PAK_SIZE = 512;			//Max Packet Size
	private static final int REPLY_TIMEOUT = 5000;				//Timeout after 4 sec
	private static final String AU_ROOT_IP = "192.58.128.30";	//ROOT IP Adress
	private static int nsCount = 1;								//Keeps track of the number of server replys it has encountered




	public static void main(String args[]) throws Exception{
		//String askfor = "www.youtube.com";		//WORKS: +FIX_TEST+ arc.gov.au NS doe not reply, needs to try next ns (Works)
                //resolveDomain(askfor,true);

		resolveDomain(args[0],true);
		//GAME OVER.. 
	}
	
	
	/**
	 * This method returns a byte from a bitset.
	 * @param askfor The domain name we are looking for.
	 * @param printFound Sets weather it should print if the domain IP has been found.
	 * @return String A string IP adress.
	 */  
	private static String resolveDomain(String askfor, boolean printFound) throws Exception{
		String at = AU_ROOT_IP;	//Holds the IP to ask next
		boolean found =  false; 
		DNS_packet response = new DNS_packet();
		DNS_packet newResponse = new DNS_packet();
		
		
		//Keeps looping until a SOA is encountered, no response from all servers or hopefully it finds the IP
		while (!found){
		
			//CHECKS FOR ERRORS : SOA, Error Codes, NULL Return (Timeout)
			newResponse = sendPak(askfor,at);  
			if(newResponse == null || newResponse.isError()){
				//Tests for SOA record
				if(newResponse != null && newResponse.noAuthoritive()>0){
					if(newResponse.getRRAuth(0).getType()==DNS_record.TYPE_SOA_RECORD){		//1st rec
						//SOA Rec == NXDOMAIN
						System.out.println(askfor + " does not exist");
						
						return NO_IP_FOUND;
					} 
				}
			}else{
				response = newResponse;	//If not null then has answers	=> Response Changed
			}
			

			//Exhausts all possible cases given a valid Reply
			if(response.noAnswers()==0){
				//Gets the next IP to query. 
				at = getNextIP(response);	
			}else{		//Loops though answers to find if A or CNAME
				for(int i=0;i<response.noAnswers();i++){
					if(response.getRRAns(i).getType()==DNS_record.TYPE_CNAME_RECORD){	//IF CNAME ANSWER
						System.out.print("CNAME for " + askfor);
					
						//Gets CNAME	
						askfor = response.getRRAns(i).getStringData();
						
						System.out.println(" is " + askfor);
					} else if(response.getRRAns(i).getType()==DNS_record.TYPE_A_RECORD){	//If Type A (IP) Answer 
						//IP FOUND!!! WHOOO RAHHH!!!
						if(printFound) System.out.println(askfor + " = " + response.getRRAns(i).getStringData());
											
						return response.getRRAns(i).getStringData(); //RETURN IP FOUND
					}
				}
				
				//Asks to find a valid IP to query next
				at = getNextIP(response);
			}	
		}
		
		//If this point is reached no IP was resolved. CASE: All servers timed out (Highly Unlikley)
		return NO_IP_FOUND;
	}
	
	
	
	/**
	 * This method searches though a response packet and attempts to find a NS Auth IP for the question inside the packet.
	 * If it cannot find one it will attempt to resolve an NS which did not get provided with additional information (IP)
	 * If it cannot resolve the NS it will return NO_IP_FOUND.
	 * @param response A dns_packet which holds the response.
	 * @return String A string IP adress.
	 */  
	private static String getNextIP(DNS_packet response) throws Exception{
		String out = NO_IP_FOUND;
		
		//Scans for Type A records (Makes sure it only returns valid IPs which have not been tried)
		for(int i=0;i<response.noAditional();i++){
			if(!response.getRRAdd(i).isTried() 
			 && response.getRRAdd(i).getType() == DNS_record.TYPE_A_RECORD){	//TYPE A REC not tried
				out = response.getRRAdd(i).getStringData(); 	//Gets the IP
				response.getRRAdd(i).setTried();				//Sets the IP as used
				
				return out;
			}	
		}
		
		//If no ip found it recursivly calls resolveDomain to get the IP of unsolved NS for next query.
		if (out==NO_IP_FOUND && response.noAuthoritive() > 0){
			//If out is NO_IP_FOUND => no A records, try solve NS in Auth Section
			for(int i=0;i<response.noAuthoritive();i++){
				out = resolveDomain(response.getRRAuth(i).getStringData(),false);	
			
				//If NS is succesfully resolved then return NS Ip to original resolve thread
				if(out != NO_IP_FOUND) return out;	
			}
		}
		
		//CASE: No Ips or Root servers exist (CNAME only in reply=> Start from scratch)
		if(response.noAuthoritive()==0 && response.noAditional()==0) return AU_ROOT_IP;
		
	
		//CASE: All servers queried recursivly did not respond. No SOA, No error. ALL TimeOut (HIGHLY UNLIKLY)
		System.out.println("All servers timed out. Domain could not be solved.");
		return NO_IP_FOUND;
	}
	
	
	/**
	 * This function constructs a DNS packet from a domainName and sends it to a given IP adress.
	 * It deals with timeout by returning null if no reply.
	 * @param domainName The name of the domain the dns is quering for.
	 * @param ipAddr The IP adress to send query.
	 * @return DNS_packet A dns packet reply.
	 */	
	private static DNS_packet sendPak(String domainName, String ipAddr) throws Exception{
		//UDP Socket Open
		DatagramSocket clientSocket = new DatagramSocket();
		
		//Create DNS Query Packet and send
		InetAddress IPAddress = InetAddress.getByName(ipAddr); 
		DNS_packet out = new DNS_packet(domainName);
		DatagramPacket sendPacket = new DatagramPacket(out.packet(), out.packet().length, IPAddress, 53);
		clientSocket.send(sendPacket);
		
		
		//Receives DNS packet
		byte[] receiveData = new byte[DEFAULT_PAK_SIZE];
		clientSocket.setSoTimeout(REPLY_TIMEOUT);	//5sec timeout
		DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
		try{	//Try receive the data
			clientSocket.receive(receivePacket);
		}catch(InterruptedIOException iioexception){
			clientSocket.close();
			return null;	//Timeout
		}
		DNS_packet in = new DNS_packet(receiveData, domainName);
		
		
		//Prints only if it receives a reply
		System.out.println("Name server " + nsCount + ": " + ipAddr);
		nsCount++;
		
		
		//UDP Socket Close
		clientSocket.close();
		
		return in;
	}
	
}

