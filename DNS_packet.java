package ass1;

import java.util.BitSet;

/**
 * A DNS Packet and all the good stuff in it. 
 */    
public class DNS_packet {
	private byte[] data;
	
	private DNS_record[] recAns; 
	private DNS_record[] recAuth;
	private DNS_record[] recAdd;
	
	private String domain;


	/**
	 * Constructor Functions
	 */  
	public DNS_packet(){
		//EMPTY Constructor
	}
	public DNS_packet(String domainName){
		createQuery(domainName);
	}
	public DNS_packet(byte[] b, String domainName){
		data = b;
		domain = domainName;
		readRecords();
	}

	/**
	 * This method constructs the header data of a DNS query and sets the domainName to query
	 * Once called the packet is constructed as a query.
	 * @param domainName The name of the domain name we are quering.
	 */  	
	private void createQuery(String domainName){
		//Populate header
		domain = domainName;
		data = new byte[18 + domainName.length()];
		
		
		
		//TODO: Randomise DNS Packet ID
		//Bytes 0,1: ID  --NEETS TO BE RANDOMISED LATER
		data[0] = 0x00; data[1] = 0x0F;
		//Bytes 2,3: Flags
		data[2] = Byte.parseByte("00000000", 2); data[3] = Byte.parseByte("00000000", 2); 

		
		//Bytes 4,5: Question Count (1)
		data[4] = 0x00; data[5] = 0x01;
		
		//Reply Header Info(Not for requests)
		//Bytes 6,7: Answer Count, Bytes 8,9: Name Server Count, Bytes 10,11: Aditional Resource Count
		data[6] = 0x00; data[7] = 0x00; 
		data[8] = 0x00; data[9] = 0x00; 
		data[10] = 0x00; data[11] = 0x00;

			
		
		//Question Bytes:
		int ppPosition = 12; //Byte Location for prepend value (1st one is 12)
		int dnCount = 0; //Used to keep track for the name prepend count
		for(int i=0;i<domainName.length();i++){
			if(domainName.charAt(i) == '.'){
				//prepend length byte
				data[ppPosition] = (byte)(int)(dnCount);
				ppPosition += dnCount +1;
				dnCount=0; i++;
			}
			
			data[ppPosition+dnCount+1] = (byte)domainName.charAt(i);
			dnCount++;
		}
		data[ppPosition] = (byte)(dnCount);
		
		data[13 + domainName.length()] = 0x00;
		
		//Question Type; Question Class
		//QTYPE=0001:Host Domain  QCLASS=0001:Internet 
		data[14 + domainName.length()] = 0x00; data[15 + domainName.length()] = 0x01;
		data[16 + domainName.length()] = 0x00; data[17 + domainName.length()] = 0x01;
		
		readRecords();
	}
	
	/**
	 * This method will read all the records present in the packet and store them in 3 array
	 * of DNS_records. If non found it wount store anything.
	 */  
	private void readRecords(){
		//Alocates arrays
		recAns = new DNS_record[this.noAnswers()];
		recAuth = new DNS_record[this.noAuthoritive()];
		recAdd = new DNS_record[this.noAditional()];
		
		
		String rrName = "";
		int rrType;  	//two octets containing one of the RR TYPE codes.
		int rrClass; 	//two octets containing one of the RR CLASS codes.
		int rrTTL;		//a 32 bit signed integer that specifies the time interval for caching  
		
		byte[] rrData;  //For type A and AAAA recs
		String stData = "";  //For CNAME and NS
		
		//START:
		int curPos = 18 + domain.length();
		int dataLen = 0;
		int nameLen = 0;
		
		
		//Loop though all Answer Records
		for(int i=0;i<noAnswers();i++){
			if(BitMath.rrNameIsRoot(data[curPos])){
				rrName = "<Root>";	//Set the name as root
				nameLen = 1;
			} else {
				rrName  = BitMath.convStops(getLabel(curPos)); //if not then name is a pointer
				nameLen = getLabelLen(data, curPos);
			}	
			
			
			
			rrType  = BitMath.byteToShort(data,curPos+nameLen);
			rrClass = BitMath.byteToShort(data,curPos+nameLen+2);
			rrTTL   = BitMath.byteToInt(data,curPos+nameLen+4);
			dataLen = BitMath.byteToShort(data,curPos+nameLen+8);
			
			//NS Record || CNAME
			if(rrType==DNS_record.TYPE_NS_RECORD || rrType==DNS_record.TYPE_CNAME_RECORD){
				stData = getLabel(curPos+nameLen+10);
						
				recAns[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,stData);
			}else if(rrType==DNS_record.TYPE_A_RECORD){ //A Record (IP)
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAns[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			} else { //All other records , SOA
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAns[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			}
				
			
			curPos = curPos+nameLen+10+dataLen;
		}
		
		//Loop though all Authoritative Records
		for(int i=0;i<noAuthoritive();i++){
			if(BitMath.rrNameIsRoot(data[curPos])){
				rrName = "<Root>";	//Set the name as root
				nameLen = 1;
			} else {
				rrName  = BitMath.convStops(getLabel(curPos)); //if not then name is a pointer
				nameLen = getLabelLen(data, curPos);
			}
			
			rrType  = BitMath.byteToShort(data,curPos+nameLen);
			rrClass = BitMath.byteToShort(data,curPos+nameLen+2);
			rrTTL   = BitMath.byteToInt(data,curPos+nameLen+4);
			dataLen = BitMath.byteToShort(data,curPos+nameLen+8);

			//NS Record || CNAME
			if(rrType==DNS_record.TYPE_NS_RECORD || rrType==DNS_record.TYPE_CNAME_RECORD){
				stData = getLabel(curPos+nameLen+10);
										
				recAuth[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,stData);
			}else if(rrType==DNS_record.TYPE_A_RECORD){ //A Record (IP)
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAuth[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			} else { //All other records , SOA
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAuth[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			}
				
			
			curPos = curPos+nameLen+10+dataLen;
		}
		
		
		//Loop though all Aditional Records
		for(int i=0;i<noAditional();i++){	
			if(BitMath.rrNameIsRoot(data[curPos])){
				rrName = "<Root>";	//Set the name as root
				nameLen = 1;
			} else {
				rrName  = BitMath.convStops(getLabel(curPos)); //if not then name is a pointer
				nameLen = getLabelLen(data, curPos);
			}
			
			rrType  = BitMath.byteToShort(data,curPos+nameLen);
			rrClass = BitMath.byteToShort(data,curPos+nameLen+2);
			rrTTL   = BitMath.byteToInt(data,curPos+nameLen+4);
			dataLen = BitMath.byteToShort(data,curPos+nameLen+8);
			
			//NS Record || CNAME
			if(rrType==DNS_record.TYPE_NS_RECORD || rrType==DNS_record.TYPE_CNAME_RECORD){
				stData = getLabel(curPos+nameLen+10);
										
				recAdd[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,stData);
			}else if(rrType==DNS_record.TYPE_A_RECORD){ //A (IPv4)
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAdd[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			} else { //All other records AAAA->IPv6, SOA
				rrData =  new byte[dataLen];
				for(int j=0;j<dataLen;j++) rrData[j] = data[curPos+nameLen+10+j];		
				
				recAdd[i] = new DNS_record(rrName,rrType,rrClass,rrTTL,rrData);
			}
		
			curPos = curPos+nameLen+10+dataLen;
		}
		
	}
	
	/**
	 * This method populates an empty packet with an arraylist of bytes. This is used to populate
	 * the dns packet once a reply of bytes is received.
	 * @param rawData The array of bytes.
	 * @param domainName A string of the domain that has been queried for in the packet question.
	 */  
	public byte[] packet(){
		return data;
	}
	

	/**
	 * Packet Return functions
	 */  
	public boolean isResponse(){
		return BitMath.byteToBitset(data[2]).get(7);
	}
	public boolean isTruncated(){
		return BitMath.byteToBitset(data[2]).get(1);
	}
	public boolean isAuthOfDomain(){
		return BitMath.byteToBitset(data[2]).get(2);
	}
	public boolean isRecursAvail(){
		return BitMath.byteToBitset(data[3]).get(7);
	}	
	public boolean isError(){
		return (BitMath.byteToBitset(data[3]).get(0) 
			 || BitMath.byteToBitset(data[3]).get(1) 
			 || BitMath.byteToBitset(data[3]).get(2)
			 || BitMath.byteToBitset(data[3]).get(3));
	}
	/**
	 * 0: No error condition
	 * 1: Format error - The name server was unable to interpret the query. 
	 * 2: Server failure - The name server was unable to process this query due to a problem with the name server.
	 * 3: Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	 * 4: Not Implemented - The name server does not support the requested kind of query.
	 * 5: Refused - The name server refuses to perform the specified operation for policy reasons.
	 **/	
	public int errorCode(){
		BitSet bs = BitMath.byteToBitset(data[3]);
		BitSet bsNew = new BitSet();
		
		bsNew.set(0, bs.get(0));
		bsNew.set(1, bs.get(1));
		bsNew.set(2, bs.get(2));
		bsNew.set(3, bs.get(3));

		return (int)BitMath.bitsetToByte(bsNew);
	}
	
	/**
	 * Return number of records for each section
	 */  
	public int noAnswers(){
		//6,7                      		               
		return (int)BitMath.byteToShort(data,6);
	}
	public int noAuthoritive(){
		//8,9
		return (int)BitMath.byteToShort(data,8);
	}
	public int noAditional(){
		//10,11
		return (int)BitMath.byteToShort(data,10);
	}
	
	
	/**
	 * These methods return DNS_records
	 * @param i The index of the record
	 * @param i The index of the record
	 * @return DNS_record The coresponding DNS record.
	 */  
	public DNS_record getRRAns(int i){
		return recAns[i];
	}
	public DNS_record getRRAuth(int i){
		return recAuth[i];
	}
	public DNS_record getRRAdd(int i){
		return recAdd[i];
	}
	

	/**
	 * This method will check weather a specific byte is a pointer to a label in the packet.
	 * @param b The byte that needs to be checked
	 * @return boolean True if the byte is a pointer to another label.
	 */
    private boolean isPointer (byte b){
    	BitSet bits = BitMath.byteToBitset(b);
    	
    	if(bits.get(7) && bits.get(6)){
    		return true;
    	}
    	    	
    	return false;
    }      
    
	/**
	 * This method will check weather a specific byte is a pointer to a label in the packet.
	 * @param b This is an array of bytes
	 * @param offset This is the start of the pointer in the byte array.
	 * @return int A pointer offset number from 
	 */    
    private int getPointerOffset(byte[] b,int offset){   //byte b, byte b2){
    	if(!isPointer(b[offset])) return -1; //checks byte is a pointer
    	
    	byte out[] = new byte[2];
    	
    	/*						b                          b2
    	 * 0  	1  	2  	3  	4  	5  	6  	7  	8  	9	10  11  12  13  14  15
		   1 	1 	                       OFFSET
    	 */   	
    	
    	//Pads the 11s and returns new byte
    	BitSet bits  = BitMath.byteToBitset(b[offset]);
    	bits.set(6, false); 
    	bits.set(7, false);
    	out[0] = BitMath.bitsetToByte(bits);
    	out[1] = b[offset+1];
    	
    	return BitMath.byteToShort(out,0);
    }

	/**
	 * This method will recursivly using the above two functions to return a full label
	 * @param offset This is the start of the label
	 * @return String A string of the label read out
	 */        
    private String getLabel(int offset){
    	String out = "";
    	
    	while(data[offset]!= BitMath.EMPTY_BYTE){
    		if(!isPointer(data[offset])){
    			out += (char)data[offset];
    			offset++;
    		}else{
    			out += getLabel(getPointerOffset(data,offset));
    			return out;
    		}
    	}
    	
    	return out;
    }
	
	/**
	 * This function returns the full length (in sequential bytes) of any record label
	 * This is used for knowing the offset from the name which is 
	 * used to pull all other information form the record
	 * NOTE: For full length use getLabel(offset).length
	 */    
    private int getLabelLen(byte[] in, int offset){
    	//Loop until 0 byte encountered return count
    	int out = 0;
    	
    	//Loop till 0 is found (start of type
    	while(in[offset] != 0x00){
    		out++;
    		offset++;
    	}
    	
    	return out;
    }

    
    
	//????????????????????????DEBUG CODE::
	public void printState(){
		System.out.println("Is Trunc:" + this.isTruncated());
		System.out.println("Is Resp:" + this.isResponse());
		System.out.println("Is Rec Avail:" + this.isRecursAvail());
		System.out.println("Is Auth of Dom:" + this.isAuthOfDomain());
		System.out.println("Is Error:" + this.isError());
		
		
		System.out.println("Ans Count:" + this.noAnswers());
		System.out.println("Auth Count:" + this.noAuthoritive());
		System.out.println("Addit Count:" + this.noAditional());
		
		for(int i=0;i<recAns.length;i++) recAns[i].printRecord();
		for(int i=0;i<recAuth.length;i++) recAuth[i].printRecord();
		for(int i=0;i<recAdd.length;i++) recAdd[i].printRecord();
		
	}
	public void printPacket(){
		System.out.print("<<");
		
		for(int i=0;i<data.length;i++){
			System.out.print((char)data[i]);	
		}
		
		
		for(int i=0;i<data.length;i++){
			System.out.print("("+data[i]+")");
		}
		
	
		System.out.println(">>");
		
	}
	

}
