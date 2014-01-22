package ass1;

import java.util.BitSet;

/**
 * This is a helper function shared by all other classes. It contains common shared bit,byte conversion functions.
 */  
public class BitMath {
	public static final int EMPTY_BYTE = 0x00;
	
	/**
	 * This method Converts 4 bytes into an integer  signed integer value.
	 * @param b Array which holds the byte
	 * @param offset The location in the array where the Byte begins 
	 * @return int 4 Byte Integer Value
	 */
	public static int byteToInt(byte[] b, int offset) {
        int value = 0;
        for (int i = 0; i < 4; i++) {
            int shift = (4 - 1 - i) * 8;
            value += (b[i + offset] & 0x000000FF) << shift;
        }
        return value;
    }
	
	/**
	 * This method returns a bitset for the bits of the byte.
	 * @param b Byte to convert. 
	 * @return BitSet An array of booleans (index 0 coresponds to least significant bit)
	 */
    public static BitSet byteToBitset(byte b) {  
	    BitSet bits = new BitSet(8);  
	    for (int i = 0; i < 8; i++){  
	        bits.set(i, (b & 1) == 1);  
	        b >>= 1;  
	    }  
	    return bits;  
	}  	    
    
	/**
	 * This method returns a 2byte unsigned integer.
	 * @param b Byte array
	 * @param offset Location in array where the 2 bytes begin. 
	 * @return int 2byte unsigned integer.
	 */
    public static int byteToShort(byte[] b, int offset){
        short retVal;

        if (b.length == 1){
            retVal = b[0];
        }else{
            //retVal = (short)(b[offset] << 8 | b[offset+1]);
            retVal = (short)(b[offset] << 8 | b[offset+1]);
        }
        
        if(retVal < 0) return 256+retVal;
        return retVal;
    }
    
  
	/**
	 * This method returns a byte from a bitset.
	 * @param bits A bitset(array of bools) 
	 * @return byte A byte forged from the elements of the bitset ONE BYTE TO RULE ALL OTHER BYTES .
	 */    
    public static byte bitsetToByte(BitSet bits) {
        byte b = 0; //= new byte[bits.length()/8+1];
        
        for (int i=0; i<bits.length(); i++) {
            if (bits.get(i)) {
                b |= 1<<(i%8);
            }
        }
        return b;
    }
	
	/**
	 * This method returns a 1 byte String
	 * @param b Byte to convert 
	 * @return String One Byte String
	 */  
    public static String byteToString(byte b){
    	short retVal = b;
    	
    	if(retVal < 0) return Short.toString((short)(256+retVal));
    
    	return Short.toString(b);
    }
	
    
	/**
	 * This function will remove all pre-appended values which count label characters into domain separators '.'
	 * @param in String data
	 * @return String Outputs String with '.' separators
	 */  
	public static String convStops(String in){
		byte[] out = new byte[in.length()];
				
		for(int i=0;i<in.length();i++){
			//Checks if its a label element
			if(Character.isLetterOrDigit(in.charAt(i)) || in.charAt(i)=='-'  || in.charAt(i)=='_'){
				out[i] = (byte)Character.toLowerCase(in.charAt(i));
			} else { //Is label separator
				out[i] = (byte)'.';
			}
		}
	
		return new String(out).substring(1);
	}
	
	/**
	 * This method will return a String output of a 4 byte IP
	 * @param recData A byte array which holds 4 bytes. It will only read the first 4 bytes starting from 0
	 * @return String Returns String IP
	 */  
	public static String bytesToIPString (byte[] recData){
		String out = "";
		
		out += byteToString((recData[0])) + ".";
		out += byteToString((recData[1])) + ".";
		out += byteToString((recData[2])) + ".";
		out += byteToString((recData[3]));
		
		return out;
	}
	
	/**
	 * Returns weather a specific record name is a root name. IE no label.
	 * @param b The first byte of the record name. 
	 * @return boolean True if name has no label. (Root Name)
	 */  
	public static boolean rrNameIsRoot(byte b){
		if (b==0) return true;
		
		return false;
	}
	
}
