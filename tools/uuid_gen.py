import uuid

my_uuid = uuid.uuid4()
print(my_uuid)  # Output: e.g., 550e8400-e29b-41d4-a716-446655440000


my_namespace = uuid.UUID(my_uuid.hex)  # Example namespace
my_name = 'seal'  
my_uuid = uuid.uuid5(my_namespace, my_name)
print(my_uuid) 
