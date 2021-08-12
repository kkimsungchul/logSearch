package com.securus.util;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;


//파일유틸
public class FileUtilClass{

    //디렉토리 가져오기
    public ArrayList<String> getDirList(String path , ArrayList<String> logDirList){
        ArrayList<String> dirList = new ArrayList<>();

        //디렉토리 내에 파일 및 디렉토리 탐색
        for (File info : new File(path).listFiles()) {

            //디렉토리 탐색
            if (info.isDirectory()) {
                for(int i=0;i<logDirList.size();i++){
                    if(logDirList.get(i).contains(info.getName())){
                        dirList.add(info.getName());
                    }
                }
            }
            //파일 탐색
            if (info.isFile()) {

            }
        }
        return dirList;
    }


    //디렉토리 내 파일 목록 가져오기
    public ArrayList<String> getFileList(String directory) {
        ArrayList<String> textFiles = new ArrayList<String>();
        File dir = new File(directory);
        for (File file : dir.listFiles()) {
            if (file.getName().endsWith((".log")) || file.getName().endsWith((".txt")) || file.getName().endsWith((""))) {
                textFiles.add(file.getName());
            }
        }
        return textFiles;
    }


    /*
    * fileList : 로그 파일 목록
    * filePath : 로그 파일 경로
    * filePath : 탐지할 단어 목록
    * filePath : 작업명 (IIS , APACHE 등)
    * saveLogDir : 분석 완료한 로그 저장 경로
    * props : 설정파일
    * fis : 파일 스트림
    * moveCompleteLog : 파일 이동 여부
    * */
    //파일목록에서 공격로그 탐지
    public ArrayList<String> attackDetection(List<String> fileList , String filePath , String[] blackList,String workName , String saveLogDir , Properties props,FileInputStream fis,String moveCompleteLog)
            throws Exception{

        ArrayList<String> returnList = new ArrayList();
        String aaa;
        String custString="";
        String originalReadLine="";
        String exceptString="";
        int startSearchIndex=0;
        int addIndex=0;
        int lineNumber=0;

//        if(filePath.contains(workName)){

        //로그의 라인에서  검색 시작 위치 지정
        props.load(new java.io.BufferedInputStream(fis));
        exceptString = new String(props.getProperty(workName+"ExceptString").getBytes("ISO-8859-1"), "utf-8");
        System.out.println("#### 검색 시작 위치 : " + exceptString);
//        }


        for(int i=0;i<fileList.size();i++){
            try{

                //넘어온 경로가 파일인지 폴더인지 체크,
                //폴더일 경우 해당 디렉토리에서 읽을 라인이 없음
                File f = new File(filePath+fileList.get(i));
                lineNumber=0;
                if(f.isFile()){

                    FileReader rw = new FileReader(filePath+fileList.get(i));
                    BufferedReader br = new BufferedReader( rw );
                    //읽을 라인이 없을 경우 br은 null을 리턴한다.
                    String readLine = null ;
                    //로그파일 읽기
                    while( ( readLine =  br.readLine()) != null ){


                        lineNumber++;
                        startSearchIndex = readLine.indexOf(exceptString);
                        if(startSearchIndex<0){
                            startSearchIndex = 0;
                        }else{
                            startSearchIndex = addIndex;
                        }
                        originalReadLine = readLine;
                        readLine= readLine.substring(startSearchIndex);
                        returnList = searchBlackList(returnList , blackList , fileList.get(i) , readLine , originalReadLine,lineNumber);
                    }
                    rw.close();
                    br.close();
                }
            }catch ( IOException e ) {
                System.out.println(e);
            }

            moveFile(filePath+fileList.get(i),saveLogDir + "\\"+fileList.get(i),moveCompleteLog);
        }





        return returnList;
    }



    //블랙리스트 문자열 탐색
    /*
     * returnList : 탐지된 목록 리스트
     * blackList : 탐지할 단어 배열
     * fileName : 현재 탐지중인 파일 이름
     * readLine : 현재 탐지하는 라인
     * originalReadLine : 현재 탐지하는 라인의 원본
     * targetLine : 파라메터 부분
     * subStringStartIndex : 자를 라인의 위치
     * */
    public ArrayList<String> searchBlackList(ArrayList<String > returnList , String[] blackList, String fileName , String readLine , String originalReadLine,int lineNumber){

        int overlapLineCheck =0;
        String targetLine="";
        int getByte=originalReadLine.getBytes().length;

        int subStringStartIndex = 0;
        if(getByte>=1024){
            returnList.add("검출된 파일 : " + fileName + "\r\n");
            returnList.add("검출된 단어 : 해당 문자열의 길이가 1024바이트를 초과하였습니다. \r\n");
            returnList.add("검출된 라인 : " + originalReadLine + "\r\n");
            returnList.add("검출된 라인 번호 : " + lineNumber + "\r\n");
            returnList.add("------------------------------------" + "\r\n");
            //db insert문으로 변경
        }

        //블랙리스트 문자열 검색
        for(int j=0; j<blackList.length;j++){
            //중복라인 검출을 막기위해 추가
            if(overlapLineCheck==1){
                break;
            }
            //파라메터가 있는 경우에만 검사
            subStringStartIndex = readLine.indexOf("?");
            if(subStringStartIndex<0){
                break;
            }


            targetLine = readLine.substring(subStringStartIndex);

            if(targetLine.contains(blackList[j])){
                returnList.add("검출된 파일 : " + fileName + "\r\n");
                returnList.add("검출된 단어 : " + blackList[j] + "\r\n");
                returnList.add("검출된 라인 : " + originalReadLine + "\r\n");
                returnList.add("검출된 라인 번호 : " + lineNumber + "\r\n");
                returnList.add("------------------------------------" + "\r\n");
                overlapLineCheck=1;
            }
        }
        return returnList;
    }



    //탐지된 목록 저장
    /*
    * outList : 탐지된 목록이 저장된 리스트
    * filePath : 파일 저장 경로
    * */
    public void saveFile(ArrayList<String> outList , String filePath){
        String saveFileName;
        String saveDirName;
        SimpleDateFormat format1 = new SimpleDateFormat ( "yyyyMMdd");
        SimpleDateFormat format2 = new SimpleDateFormat ( "yyyyMM");
        Date time = new Date();
        saveFileName = format1.format(time);
        saveDirName = format2.format(time);
        //현재는 날짜로만 디렉토리 이름을 구분하고 있지만, 한군대다가 모으게된다면 아래의 내용을 IF문으로 분기
        String saveFilePath = filePath  + saveDirName;

        //디렉토리 생성, 있을경우 아무작업도 안함
        mkDir(saveFilePath);

         for(int a=0;a<outList.size();a++){

            //저장할 라인 한줄씩 출력
            //System.out.println(outList.get(a));
            String message = outList.get(a);

            File file = new File(saveFilePath + "\\" +  saveFileName + "_analysis_log.txt");
            FileWriter writer = null;

            try {
                // 기존 파일의 내용에 이어서 쓰려면 true를, 기존 내용을 없애고 새로 쓰려면 false를 지정한다.
                writer = new FileWriter(file, true);
                writer.write(message);
                writer.flush();


            } catch(IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if(writer != null) writer.close();
                } catch(IOException e) {
                    e.printStackTrace();
                }
            }
        }

    }

    //로그저장 폴더 생성 (월별로 생성)
    public void mkDir(String filePath){
        File Folder;


        String[] filePathSplit = filePath.split("\\\\");

        ArrayList<String> mkDirPath = new ArrayList<>();
        String temp="";

        for(int a=0;a<filePathSplit.length;a++){
            temp +=  filePathSplit[a]+"\\";

            Folder = new File(temp);
            // 해당 디렉토리가 없을경우 디렉토리를 생성합니다.
            if (!Folder.exists()) {
                try{
                    Folder.mkdir(); //폴더 생성합니다.
                    System.out.println(temp + " 폴더가 생성되었습니다.");
                }
                catch(Exception e){
                    e.getStackTrace();
                }
            }else {
                //System.out.println(temp + "이미 폴더가 있습니다.");
            }
        }
    }



    //분석한 로그파일 이동
    /*
    * readFilePath : 읽은 파일 경로
    * moveDirPath : 이동할 파일 경로와 파일명
    * moveCompleteLog : 파일 이동 여부 ( YES , NO 옵션값 )
    *
    * */
    public void moveFile(String readFilePath , String moveDirPath , String moveCompleteLog ) {

        //파일을 이동할지 여부 확인
        if(moveCompleteLog.equalsIgnoreCase("NO")){
            return;
        }
        //넘어온 경로가 파일인지 폴더인지 체크,
        //파일이 없을경우 디렉토리의경로를 가지고 들어오기때문에 체크해줘야함
        File f = new File(readFilePath);
        if(!f.isFile()){
            return ;
        }
        //이미 파일이 있을 경우를 체크하여 존재할 경우 _copy 를 붙임
        while(true){
            f = new File(moveDirPath);
            if(f.exists()){
                moveDirPath = moveDirPath+"_copy";
            }else{
                break;
            }
        }

        System.out.println("### 파일 이동 완료 "  + readFilePath + " -> " + moveDirPath);

        try {
            Path filePath = Paths.get(readFilePath);

            Path filePathToMove = Paths.get(moveDirPath);

            Files.move(filePath, filePathToMove);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}



