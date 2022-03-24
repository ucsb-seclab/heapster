FROM ubuntu:18.04

RUN apt-get update && apt-get install -y htop screen git vim parallel nano\ 
                                         wget cmake python3-pip ranger zsh zplug wget\
                                         graphviz libgraphviz-dev gcc-arm*

RUN mkdir /root/heapster

# Some alias
RUN alias pip='pip3'
RUN alias python='python3'

# Some python stuff
RUN pip3 install wget 
RUN pip3 install SQLAlchemy
RUN pip3 install ipython

WORKDIR /

# Setup ZSH :) 
RUN mkdir /.heapster-env-conf
WORKDIR /root/.heapster-env-conf
ADD ./heapster-env-conf .
RUN cp .zshrc /root/ 
RUN chsh -s /bin/zsh

WORKDIR /root/heapster
ADD ./angr_taint_engine ./angr_taint_engine 
ADD ./angr-cli ./angr-cli
ADD ./angr-dev ./angr-dev
ADD ./heaphopper ./heaphopper
ADD ./heaphopper_analyses ./heaphopper_analyses

RUN mkdir heapster
WORKDIR /root/heapster/heapster
ADD ./heapster .

WORKDIR /root/fw-dataset
ADD ./fw-dataset .

# Install angr by module one by one (ignore warnings)
WORKDIR /root/heapster/angr-dev
RUN cd angr && pip3 install . 
RUN cd archinfo && pip3 install . 
RUN cd claripy && pip3 install . 
RUN cd cle && pip3 install . 
RUN cd pyvex && pip3 install .
RUN cd monkeyhex && pip3 install . 
RUN cd mulpyplexer && pip3 install . 
RUN cd ailment && pip3 install . 

# Install heapter requirements 
WORKDIR /root/heapster/heapster
RUN pip3 install -r requirements.txt

# Install angr-taint-engine
WORKDIR /root/heapster/angr_taint_engine
RUN pip3 install . 

# Install angr-cli for debugging convenience
WORKDIR /root/heapster/angr-cli
RUN pip3 install . 

# Done!
WORKDIR /root/heapster/
