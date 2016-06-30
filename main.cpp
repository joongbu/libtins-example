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
using namespace std;
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
            cout<<"name :"<<stu[i].name<<endl;
            cout<<"start time :"<<stu[i].s_time<<"last time :"<<stu[i].l_time<<endl;
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
    if (it != ssids.end()) {
        // First time we encounter this BSSID.
        try {
            //info.time_log();
            for(i = 0; i<size ; i++)
            {
                if(addr == stu[i].mac && stu[i].s_time == "0")
                {
                    stu[i].check = true;
                    stu[i].s_time = ctime(&now);
                }
                it = ssids.find(stu[i].mac);
                if(addr == stu[i].mac && stu[i].l_time == "0")
                    stu[i].l_time = ctime(&now);
                if(addr == stu[i].mac && stu[i].l_time != "0")
                    stu[i].l_time = ctime(&now);
            }

        }
        catch (runtime_error&) {
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
    stu[2].mac = "48:59:29:f4:a5:87";
    for(i=0;i<size;i++)
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
    int select;
    while(1)
    {
        printf("\e[1;1H\e[2J");
        cout<<"0. let's save student impormation"<<endl;
        cout<<"1. view student attendance"<<endl;
        cout<<"2. view student attendance log"<<endl;
        cout<<"3. quit(0)"<<endl;
        cin>>select;
        switch(select)
        {
        case 0 :
            printf("\e[1;1H\e[2J");
            //student_information.save_info();
            break;
        case 1:
            printf("\e[1;1H\e[2J");
            student_information.attendance();
            break;
        case 2:
            printf("\e[1;1H\e[2J");
            student_information.time_log();
            break;
        case 3:
            printf("\e[1;1H\e[2J");
            break;
        }
        if(select == 3) break;
        sleep(10);
    }
}

