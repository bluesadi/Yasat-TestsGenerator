#include "stdint.h"

void sink(int32_t a){
}

int32_t not32(int32_t a){
	return ~a;
}

int main(){
	sink(not32(139660845));
	sink(not32(16483597));
	sink(not32(842953552));
	sink(not32(2886909325));
	sink(not32(4198012701));
	sink(not32(2186245253));
	sink(not32(1894465108));
	sink(not32(2704389956));
	sink(not32(537774373));
	sink(not32(4172055804));
	sink(not32(3086403802));
	sink(not32(3944330611));
	sink(not32(2799448348));
	sink(not32(1342443069));
	sink(not32(1360595906));
	sink(not32(822344242));
	sink(not32(3937065860));
	sink(not32(2172328091));
	sink(not32(2755201133));
	sink(not32(1897436892));
	sink(not32(3143297709));
	sink(not32(1132114530));
	sink(not32(1931394964));
	sink(not32(2196255660));
	sink(not32(4154330075));
}

