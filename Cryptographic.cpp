#include "Cryptographic.h"

#include <iostream>
#include <fstream>
#include <algorithm>  
#include <random>     //std::mt19937
#include <array>

         /* ============= PRIVATE ============= */

int Cryptographic::generateSeed(int sMin, int sMax) {
	std::random_device rd;
	std::mt19937 rng(rd());
	if (sMax != 0 || sMax != 0){        //if default values are overriden
		std::uniform_int_distribution<int> uni(sMin, sMax);
		return uni(rd);
	}
	else {                            //if default values are intact
		std::uniform_int_distribution<int> uni(this->seedMin_, this->seedMax_);
		return uni(rd);
	}	
}

void Cryptographic::load(const std::string dir){
	std::ifstream file(dir);
	if (!file.is_open())
		throw std::runtime_error("unable to open file");

	std::string temp;                 //max length of 1 line = 4294967294 chars
	if (!file.eof()) {
		getline(file, temp);
		if (temp == "//key:") {             //if file has "//key:" header
			file >> temp;                   //go to next word (TO DO: throw if bad input!)
			inject(processKey(temp), temp); //( 1.(loads key, returns possition), 2.(loads code from file) )
		}
		else                          //else load as a file
			while (!file.eof()) {
				temp += "\n";
				data_.push_back(temp);
				getline(file, temp);		
			}}
	file.close();
}

void Cryptographic::saveFile(const std::string dir){
	std::ofstream file(dir);
	if (!file.is_open())
		throw std::runtime_error("unable to open file");

	if (!data_.empty()) {
		for (size_t i = 0; i < data_.size(); i++) {
			file << data_.at(i);
		}}	
	file.close();
}

void Cryptographic::saveKey(const std::string dir) {
	std::ofstream file(dir);
	if (!file.is_open())
		throw std::runtime_error("unable to open file");
	file << "//key:\n";
	int seed = generateSeed();
	file << seed * seedMin_ << ":";

	for (const auto& x : dictionary_) {
		file << static_cast<int>(x.second) + seed;
	}
	file.close();
}

int Cryptographic::processKey(const std::string& key) {
	std::string seed = "";
	size_t i = 0;
	for (; i < key.size(); i++) {
		if (key[i] == ':')
			break;
		else
			seed += key[i];
	}
	int intKey = std::stoi(seed);
	key_ =  intKey / seedMin_;
	return i + 1;
}

void Cryptographic::inject(int pos, const std::string& str) {
	std::string temp = "";

	int roll = 0;
	for (size_t i = 32; i < 127; i++) {       
		for (size_t j = 0; j < 3; j++) {            //loads numbers in groups of 3 starting from position after ':'
			temp += str[pos + i + roll - 32 + j];   //moving by 3 digits and by 1 in inner to load all digits
		}
		dictionary_[i] = static_cast<char>(std::atoi(temp.c_str()) - key_);
		roll += 2;
		temp = "";
	}
}

void Cryptographic::generateKey(){
	const int OFFSET = 32;                                          //offset of unused chars (starting point)
	std::array<int, (127 - OFFSET)> arr;                            //<int, (characters - unused)> arr;
	
	//fills array from OFFSET to 127:
	///std::iota(arr.begin(), arr.end(), 0);  //<numeric> alternative
	std::generate(arr.begin(), arr.end(), [i = OFFSET]() mutable{ 
		return i++; 
	});

	std::shuffle(arr.begin(), arr.end(),                            //set values randomly
		std::mt19937{ std::random_device{}() });   

	std::generate(arr.begin(), arr.end(), [&, i = 0] () mutable {   //assign generated values to the key
		dictionary_[i + OFFSET] = arr[i];
		i++;
		return i + OFFSET;
	});
}

void Cryptographic::displayData_(){
	for (const auto& x : data_)
		std::cout << x ;
}

void Cryptographic::displayDictionary_() {
	if (!dictionary_.empty()){
		for (const auto& x : dictionary_) {                                    
			std::cout << x.first << " " << static_cast<int>(x.first)
				<< "->" << x.second << std::endl;
		}
		std::cout << std::endl;
	}}

void Cryptographic::codeData() {
	for (auto& x : data_) 
		for (size_t i = 0; i < x.size(); i++) 
			for (const auto& y : dictionary_) 
				if (x.at(i) == y.first) {
					x.at(i) = y.second;
					break;
}}

void Cryptographic::decodeData() {
	for (auto& x : data_) 
		for (size_t i = 0; i < x.size(); i++) 
			for (const auto& y : dictionary_) 
				if (x.at(i) == y.second) {
					x.at(i) = y.first;
					break;
}}

         /* ============= PUBLIC ============= */
//can return 1 if error occures in other functions (TO DO)

bool Cryptographic::crypt(const std::string fileDir, bool overriding) {
	std::cout << ">> CRYPTING \"" << fileDir << "\"\n";
	std::cout << "- preparing storage\n";
	data_.clear();
	std::cout << "- loading file\n";
	load(fileDir);
	std::cout << "- generating key\n";
	generateKey();
	std::cout << "- crypting file\n";
	codeData();
	std::cout << "- saving key\n";
	saveKey("key_" + fileDir);
	std::cout << "- saving crypted file\n";
	if (overriding == true)
		saveFile(fileDir);
	else
		saveFile("crp_" + fileDir);
	std::cout << "DONE!\n";
	return 0;
}

bool Cryptographic::decrypt(const std::string fileDir,
	bool overriding, const std::string keyDir)
{
	std::cout << "<< DECRYPTING \"" << fileDir << "\"\n";
	std::cout << "- preparing storage\n";
	data_.clear();
	std::cout << "- loading file\n";
	load(fileDir);
	std::cout << "- loading key\n";
	if(keyDir == "")
		load("key_" + fileDir);
	else
		load(keyDir);
	std::cout << "- decrypting file\n";
	decodeData();
	std::cout << "- saving decrypted file\n";
	if (overriding == true)
		saveFile(fileDir);
	else
		saveFile("dcr_" + fileDir);
	std::cout << "DONE!\n";
	return 0;
}