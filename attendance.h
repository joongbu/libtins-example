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
typedef set<string> attendance; //ssid
ssids_type ssids;
attendance atten;
string interface;
string address; //mac address
struct student
{
    string name;
    address_type mac;
    string attendacne = "0";
    bool check = false;

};
int size = 0;
student stu[500]; //vector 이용해보기
//time
time_t curr_time;
struct tm *curr_tm;
/*
class DB
{
private :

public :
    void insertdata(int i, int select);
    void print();
};


void DB::insertdata(int i,int select)
{
    MYSQL mysql ;
    MYSQL_RES* res ;
    std::string query1 = "INSERT INTO impormation (name,mac) VALUES ('"+stu[i].name+"','"+address+"')";
    //MYSQL_ROW row ;
    mysql_init(&mysql) ;
    //int field;
    if(!mysql_real_connect(&mysql, NULL, "root","123","student_data",3306, (char *)NULL, 0))
    {
        printf("%s＼n",mysql_error(&mysql));
        exit(1) ;
    }
    printf("database connect...\n") ;
    if(mysql_query(&mysql, "USE student_data") )
    {
        printf("%s＼n", mysql_error(&mysql));
        exit(1) ;기

    }//switch로 바꾸기
    if(select == 1)
    {
        if(mysql_query(&mysql,query1.c_str()))
        {
            printf("%s＼n", mysql_error(&mysql));
            cout<<"student impormation database save"<<endl;
            exit(1) ;

        }
    }
    if(select == 2)
    {
        if(mysql_query(&mysql,query2.c_str()))
        {
            printf("%s＼n", mysql_error(&mysql));
            cout<<"attendance time log database save"<<endl;
            exit(1) ;

        }
    }
    if(select == 3)
    {
        if(mysql_query(&mysql,query3.c_str()))
        {
            printf("%s＼n", mysql_error(&mysql));
            cout<<"attendance impormation database save"<<endl;
            exit(1) ;

        }
    }

    res = mysql_store_result( &mysql );
    mysql_free_result( res ) ;
    mysql_close(&mysql) ;
}
void DB::print()
{
    MYSQL mysql ;
    MYSQL_RES* res ;
    std::string query1 = "select * from impormation";

    MYSQL_ROW row ;
    mysql_init(&mysql) ;
    int field;
    if(!mysql_real_connect(&mysql, NULL, "root","123","student_data",3306, (char *)NULL, 0))
    {
        printf("%s＼n",mysql_error(&mysql));
        exit(1) ;
    }
    printf("database connect...\n") ;
    if(mysql_query(&mysql, "USE student_data") )
    {
        printf("%s＼n", mysql_error(&mysql));
        exit(1) ;

    }
    if(mysql_query(&mysql,query1.c_str()))
    {
        printf("%s＼n", mysql_error(&mysql));
        cout<<"student impormation database save"<<endl;
        exit(1) ;

    }
    res = mysql_store_result( &mysql );
    field = mysql_num_fields(res);

            while( ( row = mysql_fetch_row( res ) ))
    {
        for(int cnt = 0 ; cnt < field ; ++cnt)
            printf("%12s",row[cnt]);
        printf("\n");
    }
    mysql_free_result( res ) ;
    mysql_close(&mysql) ;
}
*/
class clear_section
{
public :
    void time_setting();
    void log_section();
};
void clear_section::log_section()
{
    time_setting();
    if(curr_tm->tm_min / 5 == 0 && curr_tm->tm_sec == 0)
    {
        atten.clear();
    }
}
void clear_section::time_setting()
{
    curr_time = time(NULL);
    curr_tm = localtime(&curr_time);
}

class stu_info
{

public :
    friend class DB;
    typedef HWAddress<6> HW;
    void save_info();
    void time_log();
private:


};
void stu_info::save_info()
{
    int i ;
    cout<<"input number students :"<<endl;
    cin>>size;
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
                ssids.insert(stu[i].mac);
                cout<<"save"<<endl;
            }
            catch(runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
}

void stu_info::time_log()
{
    int i;
    cout << curr_tm->tm_year + 1900 << "year " << curr_tm->tm_mon + 1 << "month " << curr_tm->tm_mday << "day ";
    cout << curr_tm->tm_hour << "hour " << curr_tm->tm_min << "min "<< endl;
    for(i = 0 ; i < size ; i++)
    {
        try
        {
            attendance::iterator it = atten.find(stu[i].name);
            if(it != atten.end())
                cout<<"name :"<<stu[i].name<<"mac :"<<stu[i].mac<<endl;

        }
        catch(runtime_error&)
        {
            //No ssid, just ignore it.
        }

    }
    cout<<"courrent_student : "<<i<<endl;


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
    // Get the Dot11 layer
    const Dot11ProbeRequest& probe = pdu.rfind_pdu<Dot11ProbeRequest>();
    // Get the proberequest address
    address_type addr = probe.addr2(); //802.11 header second mac address sniffing
    // Look it up in our set
    ssids_type::iterator it = ssids.find(addr);
    int i;
    if (it != ssids.end()) {
        try
        {
            for(i = 0; i<size ; i++)
            {
                if(addr == stu[i].mac)
                {
                    //attendance::iterator it1 = atten.find(stu[i].name);
                    //if(it1 == atten.end())
                    //atten.insert(stu[i].name);

                }


            }
        }
        catch (runtime_error&)
        {
        }
    }
    return true;
}

#endif // ATTENDANCE_H
