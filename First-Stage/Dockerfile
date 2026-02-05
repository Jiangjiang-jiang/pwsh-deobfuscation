FROM ubuntu:20.04

RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list \
  && sed '/security\.ubuntu\.com/d' /etc/apt/sources.list \
  && apt-get clean \
  && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
  && echo "Asia/Shanghai" > /etc/timezone \
  && apt-get update \
  && apt-get install -y wget apt-transport-https software-properties-common \
  && wget -q "https://packages.microsoft.com/config/ubuntu/20.04/packages-microsoft-prod.deb" \
  && dpkg -i packages-microsoft-prod.deb \
  && apt-get update \
  && apt-get install -y powershell dotnet-sdk-7.0 \
  && apt-get -y install tzdata \
  python3 \
  python3-pip \
  python-is-python3 \
  && mkdir pwsh

RUN pip install pythonnet tqdm

WORKDIR /pwsh
COPY ./* /pwsh/
COPY ./First-Stage /pwsh/First-Stage

RUN chmod a+x ./run.py
RUN chmod a+x ./main.py

CMD ["python", "./run.py"]
