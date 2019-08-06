all: timestampAnalysis

timestampAnalysis: timestampAnalyzer.c analysisUtils.h
	gcc timestampAnalyzer.c -o analyzer -lpcap


debug: timestampAnalyzer.c analysisUtils.h
	gcc -DDEBUG timestampAnalyzer.c -o analyzer -lpcap

clean:
	rm analyzer
