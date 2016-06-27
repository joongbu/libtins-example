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
#include <unistd.h>
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
/*=======================time*/
time_t now;

/*=======================time*/
struct student
{
    string name;
    address_type mac;
    string s_time = "0";
    string l_time = "0";
    bool check = false;

};
int size = 3;
student stu[3];
class stu_info
{

public :

    void save_info();
    void attendance();
    void time_log();
private:


};
void stu_info::save_info()
{
    int i ;
    for(i = 0 ; i < size ; i++)
    {
        cout<<"input student name :";
        cin>>stu[i].name;
        cout<<"input student mac address :";
        //cin>>stu.mac;
        scanf("%s",&stu[i].mac);
        ssids_type::iterator it = ssids.find(stu[i].mac);
        if(it == ssids.end()){
            try{
                ssids.insert(stu[i].mac);
                cout<<"save"<<endl;
            }
            catch(runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
}

void stu_info::attendance()
{
    int i;
    for(i = 0 ; i<size ; i++)
    {
        if(stu[i].check == true)
            cout<<"name :"<<stu[i].name<<"time : "<<stu[i].s_time<<"class : attandence"<<endl;
        else if(stu[i].check == false)
            cout<<"name :"<<stu[i].name<<"time : "<<stu[i].s_time<<"class : miss a class"<<endl;
    }
}
void stu_info::time_log()
{
    time(&now);
    int i;
    for(i = 0 ; i < size ; i++)
    {
        try{
            cout<<"name :"<<stu[i].name<<"start time :"<<stu[i].s_time<<"last time :"<<stu[i].l_time<<endl;
        }
        catch(runtime_error&) {
            // No ssid, just ignore it.
        }
    }
}

class probeSniffer {
public:
    void running(const string& iface);

private:
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
    time(&now);
    // Get the Dot11 layer
    const Dot11ProbeRequest& probe = pdu.rfind_pdu<Dot11ProbeRequest>();
    // Get the AP address
    address_type addr = probe.addr2(); //802.11 header second mac address sniffing
    // Look it up in our set
    stu_info info;
    ssids_type::iterator it = ssids.find(addr);
    int i;
    if (it == ssids.end()) {
        // First time we encounter this BSSID.
        try {
            /* If no ssid option is set, then Dot11::ssid will throw
                 * a std::runtime_error.
                 */
            // Save it so we don't show it again.
            ssids.insert(addr); //save address
            // Display the tuple "address - ssid".
            //info.time_log();
            for(i = 0; i<size ; i++)
            {
                if(addr == stu[i].mac)
                {stu[i].check = true;
                    stu[i].s_time = ctime(&now);
                }
                it = ssids.find(stu[i].mac);
                if(it == ssids.end())
                    stu[i].l_time = ctime(&now);
            }

        }
        catch (runtime_error&) {
            // No ssid, just ignore it.
        }
        return true;
    }
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    int i;
    // search probe request
    interface = argv[1];
    stu_info student_information;
    //student_information.save_info();
    std::thread([] {
        probeSniffer  probe;
        probe.running(interface);
    }).detach();

    stu[0].name="한승균";
    stu[0].mac ="90:00:db:bb:98:c5";
    stu[1].name="백종열";
    stu[1].mac ="64:bc:0c:68:e5:71";
    stu[2].name ="이혜빈";
    stu[3].mac = "48:59:29:f4:a5:87";
    for(i=0; i<size ; i++)
    {
        ssids_type::iterator it = ssids.find(stu[i].mac);
        if(it == ssids.end()){
            try{
                ssids.insert(stu[i].mac);
            }
            catch(runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
    while(1)
    {
        //student_information.attendance();
        student_information.time_log();
        sleep(10);
    }
}
