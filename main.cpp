#include "attendance.h"


int main(int argc, char* argv[]) {
    if (argc != 2) {
        cout << "Usage: " <<* argv << " <interface>" << endl;
        return 1;
    }
    // search probe request
    interface = argv[1];
    stu_info student_information;
    size = 3;
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

    int i;
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
            //student_information.attendance();
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
