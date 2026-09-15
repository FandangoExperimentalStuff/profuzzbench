FROM ubuntu:20.04

# Install common dependencies
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update && \
    apt-get -y install sudo \
    apt-utils \
    build-essential \
    openssl \
    clang \
    graphviz-dev \
    libcap-dev \
    git \
    autoconf \
    libgnutls28-dev \
    libssl-dev \
    llvm \
    python3-pip \
    nano \
    net-tools \
    vim \
    gdb \
    netcat \
    strace \
    wget

# Add a new user ubuntu, pass: ubuntu
RUN groupadd ubuntu && \
    useradd -rm -d /home/ubuntu -s /bin/bash -g ubuntu -G sudo -u 1000 ubuntu -p "$(openssl passwd -1 ubuntu)"

RUN chmod 777 /tmp

RUN pip3 install gcovr==4.2

# Use ubuntu as default username
USER ubuntu
WORKDIR /home/ubuntu

# Import environment variable to pass as parameter to make (e.g., to make parallel builds with -j)
ARG MAKE_OPT

# Set up fuzzers
RUN git clone https://github.com/aflnet/aflnet.git && \
    cd aflnet && \
    git checkout 96032f86d0005dfeeb41ea7b31103f1d1ff8f168 && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

RUN git clone https://github.com/profuzzbench/aflnwe.git && \
    cd aflnwe && \
    make clean all $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT

# Python 3.11 for Fandango
RUN wget -qO- https://astral.sh/uv/install.sh | sh && \
    /home/ubuntu/.local/bin/uv python install 3.11 && \
    /home/ubuntu/.local/bin/uv venv --python 3.11 /home/ubuntu/fandango && \
    /home/ubuntu/.local/bin/uv pip install --python /home/ubuntu/fandango/bin/python "fandango-fuzzer @ git+https://github.com/fandango-fuzzer/fandango.git@90e7a744c4e176f51d74ecf1350b44cb2ba54911" faker

# Set up environment variables for AFLNet
ENV WORKDIR="/home/ubuntu/experiments"
ENV AFLNET="/home/ubuntu/aflnet"
ENV PATH="${PATH}:${AFLNET}:/home/ubuntu/.local/bin:${WORKDIR}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_NO_AFFINITY=1


RUN mkdir $WORKDIR

COPY --chown=ubuntu:ubuntu fuzzing.patch ${WORKDIR}/fuzzing.patch
COPY --chown=ubuntu:ubuntu gcov.patch ${WORKDIR}/gcov.patch

# Set up environment variables for ASAN
env ASAN_OPTIONS='abort_on_error=1:symbolize=0:detect_leaks=0:detect_stack_use_after_return=1:detect_container_overflow=0:poison_array_cookie=0:malloc_fill_byte=0:max_malloc_fill_size=16777216'

# Download and compile Live555 for fuzzing
RUN cd $WORKDIR && \
    git clone https://github.com/rgaufman/live555.git && \
    cd live555 && \
    git checkout ceeb4f4 && \
    patch -p1 < $WORKDIR/fuzzing.patch && \
    ./genMakefiles linux && \
    AFL_USE_ASAN=1 make clean all $MAKE_OPT || make all

# Set up Live555 for fuzzing
RUN cd ${WORKDIR}/live555/testProgs && \
    cp ${AFLNET}/tutorials/live555/sample_media_sources/*.* ./

# Download and compile Live555 for coverage analysis
RUN cd $WORKDIR && \
    git clone https://github.com/rgaufman/live555.git live555-cov && \
    cd live555-cov && \
    git checkout ceeb4f4 && \
    patch -p1 < $WORKDIR/gcov.patch && \
    ./genMakefiles linux && \
    make CFLAGS="-fprofile-arcs -ftest-coverage" CPPFLAGS="-fprofile-arcs -ftest-coverage" CXXFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs -ftest-coverage" clean all

# Set up Live555 for coverage analysis
RUN cd ${WORKDIR}/live555-cov/testProgs && \
    cp ${AFLNET}/tutorials/live555/sample_media_sources/*.* ./

# Compile Live555 for the Fandango driver. \
# Use AFL instrumentation without the response code changes of fuzzing.patch
RUN cd $WORKDIR && \
    git clone https://github.com/rgaufman/live555.git live555-fandango && \
    cd live555-fandango && \
    git checkout ceeb4f4 && \
    patch -p1 < $WORKDIR/gcov.patch && \
    ./genMakefiles linux && \
    AFL_USE_ASAN=1 make C_COMPILER=afl-clang-fast CPLUSPLUS_COMPILER=afl-clang-fast++ LINK="afl-clang-fast++ -o" clean all $MAKE_OPT

RUN cd ${WORKDIR}/live555-fandango/testProgs && \
    cp ${AFLNET}/tutorials/live555/sample_media_sources/*.* ./

COPY --chown=ubuntu:ubuntu kill-server.sh ${WORKDIR}/kill-server
COPY --chown=ubuntu:ubuntu in-rtsp ${WORKDIR}/in-rtsp
COPY --chown=ubuntu:ubuntu in-rtsp-replay ${WORKDIR}/in-rtsp-replay
COPY --chown=ubuntu:ubuntu rtsp.dict ${WORKDIR}/rtsp.dict
COPY --chown=ubuntu:ubuntu cov_script.sh ${WORKDIR}/cov_script
COPY --chown=ubuntu:ubuntu run.sh ${WORKDIR}/run
