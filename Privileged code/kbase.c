//
//  kbase.c
//  
//
//  Created by Davide Ornaghi on 8/24/18.
//
//


/*
 clang -arch armv7 -mios-version-min=5.0
 -isysroot /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS6.0.sdk/
 */

#include <stdio.h>
#include <mach/port.h>
#include <mach/mach.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/vm_types.h>

int main(int argc, char **argv) {
    kern_return_t res = 0;
    mach_port_t ktask;
    mach_msg_type_number_t count = 0;
    vm_offset_t data;
    vm_address_t kinfo = 0x802D1C5C + 0x00000000;  // Add your slide here
    res = task_for_pid(mach_task_self(), 0, &ktask);
    if (res != KERN_SUCCESS) {
        fprintf(stderr, "Cannot get task for pid 0: %s\n", mach_error_string(res));
        return -1;
    }
    res = vm_read(ktask, kinfo, 105, &data, &count);
    if (res != KERN_SUCCESS) {
        fprintf(stderr, "vm_read failed\n");
        return -1;
    }
    fprintf(stdout, "%s\n", (unsigned char*)data);
    return 0;
}
