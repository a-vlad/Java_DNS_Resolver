package ass1;
/**
 * This is a DNS record. A DNS packet can hold many records. 
 */    
public class DNS_record {
	
	public static final int TYPE_A_RECORD = 1;		//IP adress
	public static final int TYPE_NS_RECORD = 2;		//Name server for label
	public static final int TYPE_CNAME_RECORD = 5;	//Cononical Name for domain
	public static final int TYPE_SOA_RECORD = 6;	//No such Domain
	public static final int TYPE_AAAA_RECORD = 28;	//IPv6
	
	
	private String rrName = "";		//an owner name, i.e., the name of the node to which this resource record pertains.
	private int rrType;  
	private int rrClass; 			//two octets containing one of the RR CLASS codes.
	private int rrTTL;				//a 32 bit signed integer that specifies the time interval that the resource record may be cached   
	private String rrString;  		//a variable length string of octets that describes the resource. The format of this information varies according to the TYPE and CLASS of the resource record.
	
	private boolean tried; 			//Set if record has been tried but unresponsive/errorous (w/o SOA)
	
	
	/**
	 * This is a constructor for a TYPE_A record only. 
	 */    
	public DNS_record(String recName, int recType, int recClass, int recTTL, byte[] recData){
		rrName = recName;
		rrType = recType;
		rrClass = recClass;
		rrTTL = recTTL;

		rrString = BitMath.bytesToIPString(recData);
		
		tried =  false;
	}

	/**
	 * This is a constructor for a TYPE_CNAME, TYPE_NS, TYPE_SOA, TYPE_AAAA, TYPE_* 
	 */    
	public DNS_record(String recName, int recType, int recClass, int recTTL, String recData){
		rrName = recName;
		rrType = recType;
		rrClass = recClass;
		rrTTL = recTTL;
		
		rrString = BitMath.convStops(recData);
		
		tried = false;
	}
	
	
	
	/**
	 * Record data return get functions 
	 */    
	public String getStringData(){
		return rrString;
	}
		
	public int getType(){
		return rrType;
	}
	
	public String getName(){
		return rrName;
	}
	
	//Used to keep track if a record has been used ie tried (but didnt respond or responded error)
	public void setTried(){
		tried = true;
	}
	
	public boolean isTried(){
		return tried;
	}
	
	
	
	//?????????????????????????DEBUG CODE::
	public void printRecord(){
		System.out.println("==================");
		System.out.println("rrName:" + rrName);
		System.out.println("rrType:" + rrType);
		System.out.println("rrClass:" + rrClass);
		System.out.println("rrTTL:" + rrTTL);
		//System.out.print("rrData: "); for(int i=0;i<rrData.length;i++) System.out.print((char)rrData[i]);
		//System.out.println();
		System.out.println("rrString:" + rrString);
		System.out.println("==================");
	}
	
}	
	

