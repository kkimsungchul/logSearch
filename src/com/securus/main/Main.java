package com.securus.main;


import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import com.securus.util.FileUtilClass;



public class Main {

    public static void main(String[] args)throws Exception {

        // 프로퍼티 파일 위치
        String path = System.getProperty("user.dir");
        System.out.println("Working Directory = " + path);
        String propFile = path+"\\config.properties";

        String dirPath="";
        String workName ="";
        String filePath="";
        String saveLogDir="";
        String absoluteDir="";
        String iisExceptString="";
        String exceptString="";
        String moveCompleteLog="";
        List<String> fileList;
        ArrayList<String> outList;
        ArrayList<String> dirList;
        String strBlackList;
        String arrayBlackList[];


        Properties props = new Properties();
        FileInputStream fis = new FileInputStream(propFile);
        FileUtilClass fileUtilClass = new FileUtilClass();

        int dirCount=0;
        ArrayList<String> logDirList = new ArrayList<>();

        String temp="";

        //config.properties 파일을 읽어와서 설정 값 저장
        try {


            // 프로퍼티 객체 생성
            props = new Properties();


            // 프로퍼티 파일 로딩
            props.load(new java.io.BufferedInputStream(fis));
            dirPath = new String(props.getProperty("dirPath").getBytes("ISO-8859-1"), "utf-8");
            dirCount =  Integer.parseInt(new String(props.getProperty("dirCount").getBytes("ISO-8859-1"), "utf-8"));
            absoluteDir = new String(props.getProperty("absoluteDir").getBytes("ISO-8859-1"), "utf-8");
            moveCompleteLog  = new String(props.getProperty("moveCompleteLog").getBytes("ISO-8859-1"), "utf-8");

            System.out.println("### dirCount : " + dirCount);


            if(dirCount==0){
                logDirList = fileUtilClass.getFileList(dirPath);
            }

            for(int i=1;i<=dirCount;i++){
                temp="dirName"+i;
                logDirList.add(new String(props.getProperty(temp).getBytes("ISO-8859-1"), "utf-8"));
            }

        }catch (Exception e){
            System.out.println(e);
        }

        String absolutePath=dirPath + absoluteDir;





        //작업 시작
        dirList =fileUtilClass.getDirList(dirPath , logDirList);

        for(int i=0;i<dirList.size();i++){

            for(int j=0;j<logDirList.size();j++){

                if(dirList.get(i).equalsIgnoreCase(logDirList.get(j))){
                    workName = logDirList.get(j);
                }else if(dirList.get(i).equalsIgnoreCase(logDirList.get(j))){
                    workName = logDirList.get(j);
                }else if(dirList.get(i).equalsIgnoreCase(logDirList.get(j))){
                    workName = logDirList.get(j);
                }
            }

            //분석을 완료한 로그 저장 위치
            saveLogDir = absolutePath+"\\"+workName;

            //분석을 완료한 로그 이동
            if(moveCompleteLog.equalsIgnoreCase("YES")){
                fileUtilClass.mkDir(saveLogDir);
            }


            //검색할 블랙리스트 문자열 가져오기
            System.out.println("===============================================================================================");
            System.out.println(workName + " 로그 분석을 시작합니다. ");
            System.out.println("===============================================================================================");



            strBlackList = new String(props.getProperty(workName+"BlackList").getBytes("ISO-8859-1"), "utf-8");
            arrayBlackList = strBlackList.split(",");


            //분석완료 디렉토리는 접근하지 않도록 조치
            if(dirList.get(i).contains("complete")){
                continue;
            }
            filePath = dirPath  + dirList.get(i) + "\\";
            fileList = fileUtilClass.getFileList(filePath);
            outList = fileUtilClass.attackDetection(fileList , filePath , arrayBlackList,workName,saveLogDir,props,fis , moveCompleteLog);
            fileUtilClass.saveFile(outList , filePath);

            System.out.println("===============================================================================================");
            System.out.println(workName + " 로그 분석이 완료되었습니다. ");
            System.out.println("===============================================================================================");
        }
        System.out.println("##############################################################################################");
        System.out.println("################################# 모든 작업이 종료되었습니다.#################################");
        System.out.println("##############################################################################################");
    }
}







