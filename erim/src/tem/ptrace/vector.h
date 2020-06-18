#ifndef VECTOR_H
#define VECTOR_H


typedef struct _vector
{
	size_t size;
	size_t actual_size;
	pid_t *data;
} vector;


void vector_create(vector *d)
{

	d->actual_size = d->size = 0;
	d->data = NULL;
}

void vector_append(vector *d, pid_t v)
{
	if (d->size+1 > d->actual_size)
	{
		size_t new_size;
		if (!d->actual_size) 
		{ 
			new_size = 1;
		}
		else
		{
			new_size = d->actual_size * 2;
		}
		pid_t *temp = realloc(d->data, sizeof(pid_t) * new_size);
		if (!temp)
		{
			fprintf(stderr, "Failed to extend array (new_size=%zu)\n", new_size);
			exit(EXIT_FAILURE);
		}
		d->actual_size = new_size;
		d->data = temp;
	}
	d->data[d->size] = v;
	d->size++;
}

pid_t* const vector_data(vector *d)
{
	return d->data;
}


void vector_destroy(vector *d)
{
	free(d->data);
	d->data = NULL;
	d->size = d->actual_size = 0;
}


size_t vector_size(vector *d)
{
	return d->size;
}

int vector_find(vector* d, pid_t p) {
	size_t i;
	for(i = 0; i < d->size; ++i) {
		if(d->data[i] == p) {
			return i;
		}
	}
	return -1;
}


// remove first instance from vector
int vector_remove(vector* d, pid_t p) {
	int found = -1;
	size_t i;
	for(i = 0; i < d->size; ++i) {
		if(d->data[i] == p) {
			found = i;
		}
	}
	if(found < 0) {
		return found;
	}
	memmove(d->data + found, d->data + found + 1,
			(d->size - found - 1) * sizeof(pid_t));
	d->size--;  
	return found;
}


#endif
