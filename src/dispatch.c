#include "dispatch.h"

#include <pcap.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>

#include "analysis.h"
#include <unistd.h>

#define NUM_THREADS 6
//Array of threads
pthread_t threads[NUM_THREADS];

//struct which holds the neccessary data for each packet
typedef struct Job {
  struct pcap_pkthdr *header;
  const unsigned char *packet;
  int verbose;
} Job;

//Node in a queue which contains its data and a reference to the next item
typedef struct queueItem {
  struct Job j;
  struct queueItem *next;
} queueItem;

//Queue structure which is made up of a reference to the head and the tail of the queue
typedef struct queue {
  queueItem *head;
  queueItem *tail;
} queue;

//The main queue of packets
queue *q;
//Mutex lock for accessing the queue
pthread_mutex_t queueMutex;
//Mutex lock for accessing the exit flag
pthread_mutex_t exitMutex;
//Condition variable used to put thread to sleep when there are no jobs in the queue
pthread_cond_t condQ;
//Flag which determines if SIGINT has been given
int exitFlag = 0;

//Enqueues a packet
void submitJob(Job job) {
  //allocates memory to store the new job
  queueItem *qI = malloc(sizeof(queueItem));
  if(qI == NULL) {
    perror("Failed to malloc a job");
  }
  //There is no "next" job so set pointer to null
  qI->next = NULL;
  qI->j = job;
  //Get mutex since we are accessing the queue
  pthread_mutex_lock(&queueMutex);
  //Set the previous tail's next pointer to the new job
  if(q->tail != NULL) {
    q->tail->next = qI;
  }
  //Set the tail to the new job
  q->tail = qI;
  //If the new job is the only one in the queue then make it the head
  if(q->head == NULL) {
    q->head = qI;
  }
  //No longer accessing the queue so we can release the lock
  pthread_mutex_unlock(&queueMutex);
  //There is now a job in the queue so signal a thread to wake up
  pthread_cond_signal(&condQ);
}

//Main thread loop
void* startThread(void* args) {
  while(1) {
    //determines if the exit flag was set to 1
    int broken = 0;
    Job job;
    //we are reading/updating the queue so need mutex
    pthread_mutex_lock(&queueMutex);
    //If the head is NULL there are no jobs in the queue
    while(q->head == NULL) {
      //Check if the exit flag has been set
      pthread_mutex_lock(&exitMutex);
      if(exitFlag==1) {
        broken = 1;
        //allow other threads to access the lock
        pthread_mutex_unlock(&exitMutex);
        break;
      }
      pthread_mutex_unlock(&exitMutex);
      //Put thread to sleep until it is signalled to wake when a job is enqueued
      pthread_cond_wait(&condQ, &queueMutex);
    }
    //exit flag = 1 so break out of the main while
    if(broken==1){
      break;
    }
    //we are about to change the head so store it in tmp
    queueItem *tmp = q->head;
    //dequeue the next job
    job = tmp->j;
    q->head = q->head->next;
    //if the head is now null we want the tail to also be null
    if(q->head == NULL) {
      q->tail = NULL;
    }
    //free the temporary pointer to the head
    free(tmp);
    //no longer dealing with the queue so we can unlock it
    pthread_mutex_unlock(&queueMutex);
    analyse(job.header, job.packet, job.verbose);
  }
  //Can only be here if broken out of main loop i.e. exit flag = 1
  //Unlock any mutexes that might be locked and exit
  pthread_mutex_unlock(&queueMutex);
  pthread_exit(NULL);
}

//Called when the program starts, initialises global variables
void initDispatch() {
  //Allocates a memory block for the queue; there are no jobs to queue so set head and tail to null
  q = malloc(sizeof(queue));
  q->head = NULL;
  q->tail = NULL;
  //initialise mutex and cond variables
  pthread_mutex_init(&queueMutex, NULL);
  pthread_cond_init(&condQ, NULL);
  pthread_mutex_init(&exitMutex, NULL);
  //Create all the threads and pass the address of the startThread function to them
  for(int i = 0; i < NUM_THREADS; i++) {
    if(pthread_create(&threads[i], NULL, &startThread, NULL) !=0) {
      perror("Error creating threads");
    }
  }  
  //Initialises analysis.c
  initAnalysis();
}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  //Create a job and send it to the submit job procedure
  Job t = {
    .header = header,
    .packet = packet,
    .verbose = verbose
  };
  submitJob(t);
}

//Handles SIGINT for dispatch.c
void sigDestroy() {
  //Gets mutex to change value of exit flag since it may already be in use
  //Will not cause a deadlock since no thread will permanently hold the mutex
  pthread_mutex_lock(&exitMutex);
  exitFlag = 1;
  pthread_mutex_unlock(&exitMutex);
  //Wake up all the threads because we want to finish their execution
  pthread_cond_broadcast(&condQ);  
  //Join all the threads
  for(int i = 0; i < NUM_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
  //q was malloc'd so we need to free it
  free(q);
  //Destroy the mutexes
  pthread_mutex_destroy(&queueMutex);
  pthread_cond_destroy(&condQ);
  //Call the function which handles SIGINT for analysis.c
  interruptDump();
}
