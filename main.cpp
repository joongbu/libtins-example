/*
 * Copyright (c) 2016, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <iostream>
#include <stdio.h>
#include <set>
#include <string>
#include <tins/tins.h>
#include <thread>
#include <time.h>
using std::cin;
using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;
using namespace Tins;
typedef Dot11::address_type address_type; //mac address
typedef set<address_type> ssids_type; //ssid
ssids_type ssids;
string interface;
struct student
{
    string name;
    address_type mac;

};
class probeSniffer {
public:
    void running(const string& iface);
private:
    bool timeclear();
    bool call(PDU& pdu);
};
void probeSniffer::running(const std::string& iface) {
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_rfmon(true);
    Sniffer sniffer(iface, config);
    sniffer.sniff_loop(make_sniffer_handler(this, &probeSniffer::call));
}
bool probeSniffer::call(PDU& pdu) {
    // Get the Dot11 layer
    const Dot11ProbeRequest& probe = pdu.rfind_pdu<Dot11ProbeRequest>();
    // Get the AP address
    address_type addr = probe.addr2(); //802.11 header second mac address sniffing
    // Look it up in our set
    ssids_type::iterator it = ssids.find(addr);
    if (it == ssids.end()) {
        // First time we encounter this BSSID.
        try {
            /* If no ssid option is set, then Dot11::ssid will throw
                 * a std::runtime_error.
                 */
            string ssid = probe.ssid();
            // Save it so we don't show it again.
            ssids.insert(addr); //save address
            // Display the tuple "address - ssid".
            cout << addr << " - " << ssid << endl; //get AP SSID , MAC

        }
        catch (runtime_error&) {
            // No ssid, just ignore it.
        }
    }

    return true;
}
/*
bool probeSniffer::timeclear()
{
    if(sleep(300))
        true;
    false;
}
*/
class stu_info
{

public :
    int number;
    stu_info();
    student info[1000];
    void saveinfo();
    void attendence();
};
void stu_info::attendence()
{
    time_t now;
    time(&now);
    int i;
    for(i  = 0 ; i < number ; i++)
    {
        ssids_type::iterator it = ssids.find(info[i].mac);
        if(it == ssids.end())
            cout<<info[i].name<<ctime(&now)<<endl;
        else
            cout<<info[i].name<<"not attendence"<<endl;

    }
}

void stu_info::saveinfo()
{
    int i;
    cout<<"input number of people :";
    cin >> number;

    for(i = 0 ; i < number ; i++)
    {
        cout<<"input student name :";
        cin>>info[i].name;
        cout<<endl;
        cout<<"input student mac address";
        scanf("%s",&info[i].mac);

    }
    attendence();

}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }

    // search probe request
    interface = argv[1];
    cout<<"getting probe request packet.............."<<endl;
    std::thread([] {
        probeSniffer  probe;
        probe.running(interface);
    }).detach();
    stu_info student_information;
    student_information.saveinfo();

}
