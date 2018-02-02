
/**
 * CIDR.cs
 *
 * Utility Functions for IPv4 ip addresses.
 *
 * @author Jonavon Wilcox <jowilcox@vt.edu>
 * @version Sat Jun  6 21:26:48 EDT 2009
 * @copyright Copyright (c) 2009 Jonavon Wilcox
 */
/**
 * class CIDR.
 * Holds static functions for ip address manipulation.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Net
{
    public class CIDR
    {
        /**
         * method CIDRtoMask
         * Return a netmask string if given an integer between 0 and 32. I am 
         * not sure how this works on 64 bit machines.
         * Usage:
         *     CIDR::CIDRtoMask(22);
         * Result:
         *     string(13) "255.255.252.0"
         * @param $int int Between 0 and 32.
         * @access public
         * @static
         * @return String Netmask ip address
         */
        public static string CIDRtoMask(int i)
        {
            return long2ip(-1 << (32 - i));
        }

        /**
         * method countSetBits.
         * Return the number of bits that are set in an integer.
         * Usage:
         *     CIDR::countSetBits(ip2long('255.255.252.0'));
         * Result:
         *     int(22)
         * @param $int int a number
         * @access public
         * @static
         * @see http://stackoverflow.com/questions/109023/best-algorithm-to-count-the-number-of-set-bits-in-a-32-bit-integer
         * @return int number of bits set.
         */
        public static int countSetBits(long i)
        {
		    i = i -((i >> 1) & 0x55555555);
		    i = (i & 0x33333333) +((i >> 2) & 0x33333333);
            return (int)((i +(i >> 4) & 0xF0F0F0F) * 0x1010101) >> 24;
        }

        /**
         * method validNetMask.
         * Determine if a string is a valid netmask.
         * Usage:
         *     CIDR::validNetMask('255.255.252.0');
         *     CIDR::validNetMask('127.0.0.1');
         * Result:
         *     bool(true)
         *     bool(false)
         * @param $netmask String a 1pv4 formatted ip address.
         * @see http://www.actionsnip.com/snippets/tomo_atlacatl/calculate-if-a-netmask-is-valid--as2-
         * @access public
         * @static
         * return bool True if a valid netmask.
         */
        public static bool validNetMask(string netmask)
        {
		    long netmaskl = ip2long(netmask);
		    long neg = ((~netmaskl) & 0xFFFFFFFF);
            return ((neg + 1) & neg) == 0;
        }

        /**
         * method maskToCIDR.
         * Return a CIDR block number when given a valid netmask.
         * Usage:
         *     CIDR::maskToCIDR('255.255.252.0');
         * Result:
         *     int(22)
         * @param $netmask String a 1pv4 formatted ip address.
         * @access public
         * @static
         * @return int CIDR number.
         */
        public static int maskToCIDR(string netmask)
        {
            if (validNetMask(netmask))
            {
                return countSetBits(ip2long(netmask));
            }
            else
            {
                throw new ArgumentOutOfRangeException("Invalid Netmask");
            }
        }

        /**
         * method alignedCIDR.
         * It takes an ip address and a netmask and returns a valid CIDR
         * block.
         * Usage:
         *     CIDR::alignedCIDR('127.0.0.1','255.255.252.0');
         * Result:
         *     string(12) "127.0.0.0/22"
         * @param $ipinput String a IPv4 formatted ip address.
         * @param $netmask String a 1pv4 formatted ip address.
         * @access public
         * @static
         * @return String CIDR block.
         */
        public static string alignedCIDR(string ipinput, string netmask)
        {
		    string alignedIP = long2ip((ip2long(ipinput)) & (ip2long(netmask)));
            return alignedIP + "/" + maskToCIDR(netmask);
        }

        /**
         * method IPisWithinCIDR.
         * Check whether an IP is within a CIDR block.
         * Usage:
         *     CIDR::IPisWithinCIDR('127.0.0.33','127.0.0.1/24');
         *     CIDR::IPisWithinCIDR('127.0.0.33','127.0.0.1/27');
         * Result: 
         *     bool(true)
         *     bool(false)
         * @param $ipinput String a IPv4 formatted ip address.
         * @param $cidr String a IPv4 formatted CIDR block. Block is aligned
         * during execution.
         * @access public
         * @static
         * @return String CIDR block.
         */
        public static bool IPisWithinCIDR(string ipinput, string cidr)
        {
		    string[] cidra = cidr.Split('/');
		    cidr = alignedCIDR(cidra[0], CIDRtoMask(int.Parse(cidra[1])));
            cidra = cidr.Split('/');
            long ipinputl = (ip2long(ipinput));
		    long ip1 = (ip2long(cidra[0]));
		    long ip2 = (ip1 + (long)Math.Pow(2, (32 - int.Parse(cidra[1]))) -1);
            return ((ip1 <= ipinputl) && (ipinputl <= ip2));
        }

        /**
         * method maxBlock.
         * Determines the largest CIDR block that an IP address will fit into.
         * Used to develop a list of CIDR blocks.
         * Usage:
         *     CIDR::maxBlock("127.0.0.1");
         *     CIDR::maxBlock("127.0.0.0");
         * Result:
         *     int(32)
         *     int(8)
         * @param $ipinput String a IPv4 formatted ip address.
         * @access public
         * @static
         * @return int CIDR number.
         */
        public static int maxBlock(string ipinput)
        {
            return maskToCIDR(long2ip(-(ip2long(ipinput) & -(ip2long(ipinput)))));
        }

        /**
         * method rangeToCIDRList.
         * Returns an array of CIDR blocks that fit into a specified range of
         * ip addresses.
         * Usage:
         *     CIDR::rangeToCIDRList("127.0.0.1","127.0.0.34");
         * Result:
         *     array(7) { 
         *       [0]=> string(12) "127.0.0.1/32"
         *       [1]=> string(12) "127.0.0.2/31"
         *       [2]=> string(12) "127.0.0.4/30"
         *       [3]=> string(12) "127.0.0.8/29"
         *       [4]=> string(13) "127.0.0.16/28"
         *       [5]=> string(13) "127.0.0.32/31"
         *       [6]=> string(13) "127.0.0.34/32"
         *     }
         * @param $startIPinput String a IPv4 formatted ip address.
         * @param $startIPinput String a IPv4 formatted ip address.
         * @see http://null.pp.ru/src/php/Netmask.phps
         * @return Array CIDR blocks in a numbered array.
         */
        public static List<string> rangeToCIDRList(string startIPinput, string endIPinput = null)
        {
            List<string> listCIDRs = new List<string>();
            long start = ip2long(startIPinput);
		    long end = (endIPinput == null) ? start: ip2long(endIPinput);
            while (end >= start) {
			    int maxsize = maxBlock(long2ip(start));
			    int maxdiff = 32 - (int)(Math.Log(end - start + 1) / Math.Log(2));
			    int size = (maxsize > maxdiff) ? maxsize : maxdiff;
			    listCIDRs.Add(long2ip(start) + "/" + (long)size);
			    start += (long)Math.Pow(2, (32 - size));
            }
            return listCIDRs;
        }

        /**
	 * method cidrToRange.
	 * Returns an array of only two IPv4 addresses that have the lowest ip
         * address as the first entry. If you need to check to see if an IPv4
         * address is within range please use the IPisWithinCIDR method above.
	 * Usage:
	 *     CIDR::cidrToRange("127.0.0.128/25");
	 * Result:
         *     array(2) {
         *       [0]=> string(11) "127.0.0.128"
         *       [1]=> string(11) "127.0.0.255"
         *     }
	 * @param $cidr string CIDR block
	 * @return Array low end of range then high end of range.
	 */
        public static string[] cidrToRange(string cidr)
        {
            string[] range = new string[] {"1","2"};
            string[] cidra = cidr.Split('/');
		    range[0] = long2ip((ip2long(cidra[0])) & ((-1 << (32 - int.Parse(cidra[1])))));
		    range[1] = long2ip((ip2long(cidra[0])) + (long)Math.Pow(2, (32 - int.Parse(cidra[1]))) - 1);
            return range;
        }

        private static string long2ip(long ipAddress)
        {
            return BitConverter.GetBytes(ipAddress)[3] + "." + BitConverter.GetBytes(ipAddress)[2] + "." + BitConverter.GetBytes(ipAddress)[1] + "." + BitConverter.GetBytes(ipAddress)[0];
        }

        private static long ip2long(string ipAddress)
        {
            System.Net.IPAddress ip;
            if (System.Net.IPAddress.TryParse(ipAddress, out ip))
            {
                return (((long)ip.GetAddressBytes()[0] << 24) | ((long)ip.GetAddressBytes()[1] << 16) | ((long)ip.GetAddressBytes()[2] << 8) | ip.GetAddressBytes()[3]);
            }
            return -1;
        }

        /**
        method cidrDevider.
        Returns an array of splited IPv4 networks.
        Usage:
            cidrDevider("127.0.0.0/23", 24);
        Result:
            "127.0.0.0/24"
            "127.0.1.0/24"
        @param $cidr string CIDR block
        @param $dstprefix int result prefix
        @return Array of splited networks.
	    */
        public static List<string> cidrDevider(string cidr, int dstprefix) {
            List<string> listCIDRs = new List<string>();
            string[] cidra = cidr.Split('/');
	        string[] range = cidrToRange(cidr);
	        if (dstprefix < int.Parse(cidra[1])){ throw new ArgumentOutOfRangeException("Invalid Destination Prefix"); }
            long incr = (long)Math.Pow(2, (32 - dstprefix));
	        long net = ip2long(range[0]);
            do {
                listCIDRs.Add(long2ip(net) + "/" + (long)dstprefix);
		        net = net + incr;
	        } while(net <= ip2long(range[1]));
            return listCIDRs;
        }

    }
}
