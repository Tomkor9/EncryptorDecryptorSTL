#ifndef CRYPTOGRAPHIC
#define CRYPTOGRAPHIC

#include <map>
#include <deque>
#include <string>

class Cryptographic {
private:
	//STORED DATA
	std::map<unsigned char, unsigned char> dictionary_;
	std::deque<std::string> data_;
	int key_ = 0;                               //loaded key value

	//KEY CRYPT OPTIONS
	int seedMin_ = 70;                          //extends char to int to fit 3 digits (2 min)
	int seedMax_ = 872;                         //must be contained in 3 digit value (872 max)

	//INTERNAL METHODS
	int processKey(const std::string& key);       //loads key, returns pos of first char
	void inject(int pos, const std::string& str); //loads content to map acording to the key
	void load(const std::string dir);             //loads automaticly content of file or key
	void saveFile(const std::string dir);         //saves file in given directory
	void saveKey(const std::string dir);          //saves key in given directory
	void generateKey();                           //re-rolls asocieated char and nums
	int generateSeed(int sMin = 0, int sMax = 0); //generates seed to crypt the key
	void codeData();                              //changes data_ acording to map values 2
	void decodeData();                            //changes data_ back acording to map values 1

	//DEBUG - DISABLED
	void displayData_();
	void displayDictionary_();

public:
	
	//MAIN METHODS
	bool crypt(const std::string fileDir, bool overriding = false);
	bool decrypt(const std::string fileDir,
		bool overriding = false, const std::string keyDir = "");
};
#endif // !CRYPTOGRAPHIC