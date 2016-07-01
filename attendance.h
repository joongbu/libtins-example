#ifndef ATTENDANCE_H
#define ATTENDANCE_H
#include <iostream>
#include <stdio.h>
#include <set>
#include <string>
#include <tins/tins.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <errno.h>

using std::cin;
using std::set;
using std::cout;
using std::endl;
using std::string;
using std::runtime_error;
using namespace std;
using namespace Tins;
typedef Dot11::address_type address_type; //mac address
typedef set<address_type> ssids_type; //ssid
ssids_type ssids;
string interface;
/*=======================time*/
time_t now;
/*=======================time*/
string address; //mac address
struct student
{
    string name;
    address_type mac;
    string s_time = "0";
    string l_time = "0";
    string attendacne = "0";
    bool check = false;

};
int size = 3;
student stu[3];
class DB
{
public :
    void insertdata(int i, int select);
};
void DB::insertdata(int i,int select)
{
    MYSQL mysql ;
    MYSQL_RES* res ;
     std::string query1 = "INSERT INTO impormation (name,mac) VALUES ('"+stu[i].name+"','"+address+"')";
     std::string query2 = "INSERT INTO timelog (name,start_time,last_time) VALUES ('"+stu[i].name+"','"+stu[i].s_time+"','"+stu[i].l_time+"')";
     std::string query3 = "INSERT INTO attendance (name,attendance) VALUES ('"+stu[i].name+"','"+stu[i].attendacne+"')";
    //MYSQL_ROW row ;
    mysql_init(&mysql) ;
    //int field;
    if(!mysql_real_connect(&mysql, NULL, "root","123","student_data",3306, (char *)NULL, 0))
    {
        printf("%s＼n",mysql_error(&mysql));
        exit(1) ;
    }
    printf("성공적으로 연결되었습니다.\n") ;
    if(mysql_query(&mysql, "USE student_data") )
    {
        printf("%s＼n", mysql_error(&mysql));
        exit(1) ;

    }
    if(select == 1)
    {
    if(mysql_query(&mysql,query1.c_str()))
    {
        printf("%s＼n", mysql_error(&mysql));
        //exit(1) ;

    }
    }
    if(select == 2)
    {
    if(mysql_query(&mysql,query2.c_str()))
    {
        printf("%s＼n", mysql_error(&mysql));
        //exit(1) ;

    }
    }
    if(select == 3)
    {
    if(mysql_query(&mysql,query3.c_str()))
    {
        printf("%s＼n", mysql_error(&mysql));
        //exit(1) ;

    }
    }

    res = mysql_store_result( &mysql );
    //field = mysql_num_fields(res);
    //database table impormation print
    /*
while( ( row = mysql_fetch_row( res ) ))
{
    for(int cnt = 0 ; cnt < field ; ++cnt)
    printf("%12s",row[cnt]);
    printf("\n");
}
*/
    mysql_free_result( res ) ;
    mysql_close(&mysql) ;
}
class stu_info
{

public :
    friend class DB;
    typedef HWAddress<6> HW;
    void save_info();
    void attendance();
    void time_log();
private:


};
void stu_info::save_info()
{
    DB db;
    int i ;
    for(i = 0 ; i < size ; i++)
    {
        cout<<"input student name :";
        cin>>stu[i].name;
        cout<<"input student mac address :";
        cin>>address;
        stu[i].mac = HW(address);
        ssids_type::iterator it = ssids.find(stu[i].mac);
        if(it == ssids.end()){
            try{
                db.insertdata(i,1); //database
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
    DB db;
    int i;
    for(i = 0 ; i<size ; i++)
    {
        if(stu[i].check == true)
        {
            cout<<"name :"<<stu[i].name<<"time : "<<stu[i].s_time<<"class : "<<stu[i].attendacne<<endl;
            db.insertdata(i,3);
        }
        else if(stu[i].check == false)
            cout<<"name :"<<stu[i].name<<"time : "<<stu[i].s_time<<"class : miss a class"<<endl;
    }
}
void stu_info::time_log()
{
    DB db;
    time(&now);
    int i;
    for(i = 0 ; i < size ; i++)
    {
        try{
            cout<<"name :"<<stu[i].name<<endl;
            cout<<"start time :"<<stu[i].s_time<<"last time :"<<stu[i].l_time<<endl;
            if(stu[i].s_time != "0" && stu[i].l_time != "0")
            db.insertdata(i,2);
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
    ssids_type::iterator it = ssids.find(addr);
    int i;
    if (it != ssids.end()) {
        // First time we encounter this BSSID.
        try {
            for(i = 0; i<size ; i++)
            {
                if(addr == stu[i].mac && stu[i].s_time == "0")
                {
                    stu[i].check = true;
                    stu[i].attendacne = "attendance";
                    stu[i].s_time = ctime(&now);
                }
                if(addr == stu[i].mac && stu[i].l_time == "0")
                    stu[i].l_time = ctime(&now);
                if(addr == stu[i].mac && stu[i].l_time != "0")
                    stu[i].l_time = ctime(&now);
            }


        }
        catch (runtime_error&) {
        }

    }
    return true;
}
#endif // ATTENDANCE_H
